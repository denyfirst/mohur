// Command mohur-lab runs several Mohur organizations on this computer for
// development and the app's end-to-end tests: a private test CA, a small DNS
// server, and one real mohurd per organization, set up and connected. It
// writes everything a test needs to lab.json. Nothing here is for production.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/labdns"
	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/server"
	"github.com/denyfirst/mohur/internal/store"
)

type labOrg struct {
	Domain   string `json:"domain"`
	Server   string `json:"server"`
	Listen   string `json:"listen"`
	Admin    string `json:"admin"`
	Password string `json:"password"`
	Seed     string `json:"seed"`

	client *http.Client
}

type labFile struct {
	Resolver string             `json:"resolver"`
	CA       string             `json:"ca"`
	Orgs     map[string]*labOrg `json:"orgs"`
	Invites  map[string]string  `json:"invites"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mohur-lab:", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run() error {
	dir := flag.String("dir", ".work/lab", "lab directory")
	orgs := flag.String("orgs", "alpha.test,beta.test", "organization domains")
	noConnect := flag.Bool("no-connect", false, "leave the organizations unconnected")
	var invites multi
	flag.Var(&invites, "invite", "domain:username:Full Name, repeatable")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	ca, caKey, caPEM, err := makeCA()
	if err != nil {
		return err
	}
	caFile := filepath.Join(*dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		return err
	}
	dns, err := labdns.Start("127.0.0.1:0")
	if err != nil {
		return err
	}
	defer dns.Close()
	addrs := map[string]string{}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	clientFor := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				var d net.Dialer
				return d.DialContext(ctx, network, addrs[host])
			}}}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	out := labFile{Resolver: dns.Addr(), CA: caFile, Orgs: map[string]*labOrg{}, Invites: map[string]string{}}
	var list []*labOrg
	for _, domain := range strings.Split(*orgs, ",") {
		host := "mohur." + domain
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		addrs[host] = ln.Addr().String()
		dns.SetA(host, net.IPv4(127, 0, 0, 1))
		odir := filepath.Join(*dir, domain)
		_ = os.RemoveAll(odir)
		st, err := store.Open(odir, filepath.Join(odir, "instance.key"))
		if err != nil {
			return err
		}
		disc, err := discover.New(discover.Config{Resolver: dns.Addr(), ExtraRoots: []*x509.Certificate{ca}, AllowPrivate: true})
		if err != nil {
			return err
		}
		srv := server.New(st, disc, log)
		cert, err := leaf(ca, caKey, host)
		if err != nil {
			return err
		}
		hs := &http.Server{Handler: srv.Handler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = hs.ServeTLS(ln, "", "") }()
		o := &labOrg{Domain: domain, Server: host + ":" + port, Listen: ln.Addr().String(), Admin: "admin", Password: "lab password for " + domain, client: clientFor()}
		code, err := st.NewSetupCode()
		if err != nil {
			return err
		}
		var start struct {
			Seed string `json:"seed"`
		}
		if err := o.call("setup/start", map[string]any{"code": code}, &start); err != nil {
			return err
		}
		o.Seed = start.Seed
		name := strings.ToUpper(domain[:1]) + domain[1:strings.Index(domain, ".")] + " LLC"
		if err := o.call("setup/finish", map[string]any{"code": code, "orgName": name, "domain": domain, "server": o.Server,
			"username": o.Admin, "password": o.Password, "totp": store.TOTP(o.Seed, time.Now())}, nil); err != nil {
			return err
		}
		var doc proto.OrgDoc
		if err := o.get("/.well-known/mohur", &doc); err != nil {
			return err
		}
		key, err := doc.Check()
		if err != nil {
			return err
		}
		dns.SetTXT("_mohur."+domain, proto.TXTValue(o.Server, key))
		out.Orgs[domain] = o
		list = append(list, o)
	}
	if !*noConnect {
		for i := range list {
			for j := i + 1; j < len(list); j++ {
				if err := list[i].call("partners/connect", map[string]any{"domain": list[j].Domain}, nil); err != nil {
					return err
				}
				if err := list[j].call("partners/accept", map[string]any{"domain": list[i].Domain}, nil); err != nil {
					return err
				}
			}
		}
	}
	for _, inv := range invites {
		parts := strings.SplitN(inv, ":", 3)
		if len(parts) != 3 || out.Orgs[parts[0]] == nil {
			return fmt.Errorf("bad -invite %q", inv)
		}
		var res struct {
			Invite string `json:"invite"`
		}
		// In the lab, everyone invited may write with every partner.
		partners := []string{}
		if !*noConnect {
			for _, o := range list {
				if o.Domain != parts[0] {
					partners = append(partners, o.Domain)
				}
			}
		}
		if err := out.Orgs[parts[0]].call("people/invite", map[string]any{"username": parts[1], "name": parts[2], "partners": partners}, &res); err != nil {
			return err
		}
		out.Invites[parts[1]+"@"+parts[0]] = res.Invite
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(filepath.Join(*dir, "lab.json"), b, 0o600); err != nil {
		return err
	}
	fmt.Println("READY", filepath.Join(*dir, "lab.json"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// Also stop when whoever started us closes our input.
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); stop() }()
	<-ctx.Done()
	return nil
}

func (o *labOrg) call(path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, _ := http.NewRequest("POST", "https://"+o.Server+"/admin/api/"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Mohur", "1")
	return o.do(req, out)
}

func (o *labOrg) get(path string, out any) error {
	req, _ := http.NewRequest("GET", "https://"+o.Server+path, nil)
	return o.do(req, out)
}

func (o *labOrg) do(req *http.Request, out any) error {
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s %s: %d %s", o.Domain, req.URL.Path, resp.StatusCode, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func makeCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mohur lab CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{".test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	ca, err := x509.ParseCertificate(der)
	return ca, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
}

func leaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
