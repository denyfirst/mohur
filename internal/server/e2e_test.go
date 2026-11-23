package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/labdns"
	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
)

// lab is two or more organizations on this computer: a test CA, a DNS server
// and one real HTTPS mohurd per organization.
type lab struct {
	t     *testing.T
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	dns   *labdns.Server
	addrs map[string]string // host -> listener address
}

type org struct {
	lab     *lab
	domain  string
	server  string // host:port
	srv     *Server
	st      *store.Store
	admin   *http.Client
	key     ed25519.PublicKey
	keyFile string // the instance key, for reset codes
}

func newLab(t *testing.T) *lab {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mohur test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	dns, err := labdns.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close() })
	return &lab{t: t, ca: ca, caKey: caKey, dns: dns, addrs: map[string]string{}}
}

func (l *lab) cert(host string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, l.ca, &key.PublicKey, l.caKey)
	if err != nil {
		l.t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// client is an HTTPS client that trusts the lab CA and finds lab hosts.
func (l *lab) client(jar http.CookieJar) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(l.ca)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		var d net.Dialer
		return d.DialContext(ctx, network, l.addrs[host])
	}}
	return &http.Client{Transport: tr, Jar: jar, Timeout: time.Minute}
}

// start runs a mohurd for domain, finishes setup and publishes its DNS record.
func (l *lab) start(domain string) *org {
	t := l.t
	host := "mohur." + domain
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	l.addrs[host] = ln.Addr().String()
	l.dns.SetA(host, net.IPv4(127, 0, 0, 1))
	dir := t.TempDir()
	st, err := store.Open(dir, dir+"/instance.key")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	disc, err := discover.New(discover.Config{Resolver: l.dns.Addr(), ExtraRoots: []*x509.Certificate{l.ca}, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, disc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cert := l.cert(host)
	hs := &http.Server{Handler: srv.Handler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = hs.Close() })

	jar, _ := cookiejar.New(nil)
	o := &org{lab: l, domain: domain, server: host + ":" + port, srv: srv, st: st, admin: l.client(jar), keyFile: dir + "/instance.key"}
	code, err := st.NewSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	var start struct {
		Seed string `json:"seed"`
	}
	o.adminCall("setup/start", map[string]any{"code": code}, &start, 200)
	o.adminCall("setup/finish", map[string]any{"code": code, "orgName": strings.ToUpper(domain[:1]) + domain[1:strings.Index(domain, ".")] + " LLC",
		"domain": domain, "server": o.server, "username": "admin", "password": "correct horse battery staple", "totp": store.TOTP(start.Seed, time.Now())}, nil, 200)

	var doc proto.OrgDoc
	o.get("/.well-known/mohur", &doc, 200)
	o.key, err = doc.Check()
	if err != nil {
		t.Fatal(err)
	}
	l.dns.SetTXT("_mohur."+domain, proto.TXTValue(o.server, o.key))
	return o
}

func (o *org) url(path string) string { return "https://" + o.server + path }

func (o *org) adminCall(path string, in, out any, want int) {
	o.lab.t.Helper()
	method := "GET"
	var body io.Reader
	if in != nil {
		method = "POST"
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, o.url("/admin/api/"+path), body)
	req.Header.Set("X-Mohur", "1")
	req.Header.Set("Origin", "https://"+o.server)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	o.do(req, out, want)
}

func (o *org) get(path string, out any, want int) {
	o.lab.t.Helper()
	req, _ := http.NewRequest("GET", o.url(path), nil)
	o.do(req, out, want)
}

func (o *org) do(req *http.Request, out any, want int) {
	o.lab.t.Helper()
	resp, err := o.admin.Do(req)
	if err != nil {
		o.lab.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		o.lab.t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, resp.StatusCode, want, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			o.lab.t.Fatalf("%s: %v: %s", req.URL.Path, err, b)
		}
	}
}

// device is a synthetic desktop app. Servers never look inside ciphertext, so
// random bytes stand in for libsignal's output here.
type device struct {
	org     *org
	address string
	id      uint32
	auth    ed25519.PrivateKey
	token   string
	http    *http.Client
	cert    proto.DeviceCert
}

func randomB64(n int, first byte) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	if first != 0 {
		b[0] = first
	}
	return proto.B64(b)
}

func (o *org) invite(username, name string) string {
	var res struct {
		Invite string `json:"invite"`
	}
	o.adminCall("people/invite", map[string]any{"username": username, "name": name}, &res, 200)
	return res.Invite
}

func (o *org) join(invite string, want int) *device {
	t := o.lab.t
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	in := map[string]any{"invite": invite, "label": "Test laptop", "identityKey": randomB64(33, 5), "authKey": proto.B64(pub), "registrationId": 1234,
		"signedPreKey": map[string]any{"id": 1, "pub": randomB64(33, 5), "sig": randomB64(64, 0)},
		"kyberPreKey":  map[string]any{"id": 1, "pub": randomB64(1569, 8), "sig": randomB64(64, 0)},
		"preKeys":      []map[string]any{{"id": 1, "pub": randomB64(33, 5)}, {"id": 2, "pub": randomB64(33, 5)}}}
	d := &device{org: o, auth: priv, http: o.lab.client(nil)}
	var res struct {
		Cert proto.DeviceCert `json:"cert"`
	}
	d.call("POST", "/api/v1/join", in, &res, want)
	if want != 200 {
		return nil
	}
	if err := res.Cert.Check(o.key, o.domain); err != nil {
		t.Fatalf("device certificate does not verify: %v", err)
	}
	d.cert, d.address, d.id = res.Cert, res.Cert.Address, res.Cert.Device
	d.signIn(200)
	return d
}

func (d *device) signIn(want int) {
	var ch struct {
		Nonce string `json:"nonce"`
	}
	d.call("POST", "/api/v1/session/challenge", map[string]any{"address": d.address, "device": d.id}, &ch, 200)
	sig := proto.Sign(d.auth, proto.ContextSession, d.org.domain, d.address, strconv.Itoa(int(d.id)), ch.Nonce)
	var tok struct {
		Token string `json:"token"`
	}
	d.call("POST", "/api/v1/session", map[string]any{"address": d.address, "device": d.id, "nonce": ch.Nonce, "sig": sig}, &tok, want)
	d.token = tok.Token
}

func (d *device) call(method, path string, in, out any, want int) {
	d.org.lab.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, d.org.url(path), body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		d.org.lab.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		d.org.lab.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	if out != nil && want == 200 {
		if err := json.Unmarshal(b, out); err != nil {
			d.org.lab.t.Fatalf("%s: %v", path, err)
		}
	}
}

func (d *device) upload(to string, data []byte) string {
	req, _ := http.NewRequest("POST", d.org.url("/api/v1/blobs?to="+url.QueryEscape(to)), bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+d.token)
	resp, err := d.http.Do(req)
	if err != nil {
		d.org.lab.t.Fatal(err)
	}
	defer resp.Body.Close()
	var res struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&res) != nil {
		d.org.lab.t.Fatalf("upload: %d", resp.StatusCode)
	}
	return res.ID
}

func (d *device) download(id string) ([]byte, int) {
	req, _ := http.NewRequest("GET", d.org.url("/api/v1/blobs/"+id), nil)
	req.Header.Set("Authorization", "Bearer "+d.token)
	resp, err := d.http.Do(req)
	if err != nil {
		d.org.lab.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode
}

func (d *device) inbox() []proto.Envelope {
	var res struct {
		Envelopes []proto.Envelope `json:"envelopes"`
	}
	d.call("GET", "/api/v1/inbox", nil, &res, 200)
	return res.Envelopes
}

func connect(t *testing.T, a, b *org) {
	t.Helper()
	var preview map[string]any
	a.adminCall("partners/preview", map[string]any{"domain": b.domain}, &preview, 200)
	if preview["domain"] != b.domain {
		t.Fatalf("preview = %v", preview)
	}
	var res map[string]any
	a.adminCall("partners/connect", map[string]any{"domain": b.domain}, &res, 200)
	if res["state"] != store.Outgoing {
		t.Fatalf("after connect: %v", res)
	}
	if c, err := b.st.Connection(a.domain); err != nil || c.State != store.Incoming {
		t.Fatalf("partner sees %v, %v", c.State, err)
	}
	b.adminCall("partners/accept", map[string]any{"domain": a.domain}, &res, 200)
	for _, side := range []struct{ o, other *org }{{a, b}, {b, a}} {
		c, err := side.o.st.Connection(side.other.domain)
		if err != nil || c.State != store.Connected || c.Key != proto.B64(side.other.key) {
			t.Fatalf("%s sees %s as %v (%v)", side.o.domain, side.other.domain, c.State, err)
		}
	}
}

func TestTwoOrganizationsExchangeMessagesAndFiles(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")

	var check map[string]any
	alpha.adminCall("domain/check", map[string]any{}, &check, 200)
	if check["ok"] != true {
		t.Fatalf("domain check: %v", check)
	}

	aylin := alpha.join(alpha.invite("aylin", "Aylin Məmmədova"), 200)
	kamran := beta.join(beta.invite("kamran", "Kamran Əliyev"), 200)

	// Before the organizations connect, nothing crosses.
	aylin.call("GET", "/api/v1/keys?address=kamran@beta.e2e.test", nil, nil, 403)

	connect(t, alpha, beta)
	// Until each side chooses its people, still nothing crosses.
	aylin.call("GET", "/api/v1/keys?address=kamran@beta.e2e.test", nil, nil, 403)
	alpha.adminCall("partners/access", map[string]any{"domain": "beta.e2e.test", "people": []string{"aylin"}}, nil, 200)
	beta.adminCall("partners/access", map[string]any{"domain": "alpha.e2e.test", "people": []string{"kamran"}}, nil, 200)

	var contacts struct {
		People []proto.Person `json:"people"`
		Orgs   []orgView      `json:"orgs"`
	}
	aylin.call("GET", "/api/v1/contacts", nil, &contacts, 200)
	found := false
	for _, p := range contacts.People {
		if p.Address == "kamran@beta.e2e.test" && p.Name == "Kamran Əliyev" && p.Devices[0].Check(beta.key, "beta.e2e.test") == nil {
			found = true
		}
	}
	if !found || len(contacts.Orgs) != 2 {
		t.Fatalf("contacts = %+v", contacts)
	}

	var keys struct {
		Bundles []proto.Bundle `json:"bundles"`
	}
	aylin.call("GET", "/api/v1/keys?address=kamran@beta.e2e.test", nil, &keys, 200)
	if len(keys.Bundles) != 1 || keys.Bundles[0].PreKey == nil || keys.Bundles[0].Cert.Address != "kamran@beta.e2e.test" {
		t.Fatalf("bundles = %+v", keys.Bundles)
	}

	file := bytes.Repeat([]byte("ciphertext"), 50000)
	blob := aylin.upload("kamran@beta.e2e.test", file)
	body := randomB64(200, 0)
	aylin.call("POST", "/api/v1/send", map[string]any{"envelopes": []map[string]any{{"to": "kamran@beta.e2e.test", "toDevice": kamran.id, "type": 3, "body": body, "blobs": []string{blob}}}}, nil, 200)

	got := kamran.inbox()
	if len(got) != 1 || got[0].Body != body || got[0].From != "aylin@alpha.e2e.test" || got[0].FromCert.Check(alpha.key, "alpha.e2e.test") != nil {
		t.Fatalf("inbox = %+v", got)
	}
	data, status := kamran.download(got[0].Blobs[0])
	if status != 200 || !bytes.Equal(data, file) {
		t.Fatalf("download: %d, %d bytes", status, len(data))
	}
	if _, status := aylin.download(blob); status != 404 {
		t.Fatalf("sender's server kept the file after delivery: %d", status)
	}
	kamran.call("POST", "/api/v1/inbox/ack", map[string]any{"ids": []string{got[0].ID}}, nil, 200)
	if len(kamran.inbox()) != 0 {
		t.Fatal("acknowledged envelope still queued")
	}

	// A reply the other way, and a message inside one organization.
	kamran.call("POST", "/api/v1/send", map[string]any{"envelopes": []map[string]any{{"to": "aylin@alpha.e2e.test", "toDevice": aylin.id, "type": 2, "body": body}}}, nil, 200)
	if in := aylin.inbox(); len(in) != 1 || in[0].From != "kamran@beta.e2e.test" {
		t.Fatalf("reply inbox = %+v", in)
	}
	nigar := alpha.join(alpha.invite("nigar", "Nigar"), 200)
	nigar.call("POST", "/api/v1/send", map[string]any{"envelopes": []map[string]any{{"to": "aylin@alpha.e2e.test", "toDevice": aylin.id, "type": 2, "body": body}}}, nil, 200)
	if in := aylin.inbox(); len(in) != 2 {
		t.Fatalf("local inbox = %d", len(in))
	}
}

func TestInvitesWorkOnceAndRemovedPeopleLoseAccess(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	inv := alpha.invite("aylin", "Aylin")
	aylin := alpha.join(inv, 200)
	alpha.join(inv, 403)
	alpha.join("alpha.e2e.test/AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", 403)
	alpha.join("beta.e2e.test/"+strings.SplitN(alpha.invite("other", "Other"), "/", 2)[1], 400)

	aylin.call("GET", "/api/v1/contacts", nil, nil, 200)
	alpha.adminCall("people/remove", map[string]any{"username": "aylin"}, nil, 200)
	aylin.call("GET", "/api/v1/contacts", nil, nil, 401)
	aylin.signIn(401)
}

func TestSessionNeedsTheDeviceKey(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	aylin := alpha.join(alpha.invite("aylin", "Aylin"), 200)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	aylin.auth = other
	aylin.token = ""
	aylin.signIn(401)
}

func TestAdminAPIRefusesCrossSiteAndSignedOut(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	req, _ := http.NewRequest("GET", alpha.url("/admin/api/people"), nil)
	req.Header.Set("Origin", "https://"+alpha.server)
	alpha.do(req, nil, 403) // no X-Mohur header
	req, _ = http.NewRequest("GET", alpha.url("/admin/api/people"), nil)
	req.Header.Set("X-Mohur", "1")
	req.Header.Set("Origin", "https://evil.test")
	alpha.do(req, nil, 403)
	fresh := l.client(nil)
	req, _ = http.NewRequest("GET", alpha.url("/admin/api/people"), nil)
	req.Header.Set("X-Mohur", "1")
	resp, err := fresh.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("signed-out admin call: %d", resp.StatusCode)
	}
}

// fedRaw sends a hand-built federation request from o to target.
func fedRaw(t *testing.T, o, target *org, method, path string, body []byte, mutate func(*http.Request)) int {
	t.Helper()
	req, _ := http.NewRequest(method, target.url(path), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h := sha256Sum(body)
	if err := o.srv.signRequest(req, target.domain, h); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := o.lab.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestFederationRefusesStrangersReplaysAndForgeries(t *testing.T) {
	l := newLab(t)
	alpha, beta, gamma := l.start("alpha.e2e.test"), l.start("beta.e2e.test"), l.start("gamma.e2e.test")
	aylin := alpha.join(alpha.invite("aylin", "Aylin"), 200)
	kamran := beta.join(beta.invite("kamran", "Kamran"), 200)
	connect(t, alpha, beta)
	alpha.adminCall("partners/access", map[string]any{"domain": "beta.e2e.test", "people": []string{"aylin"}}, nil, 200)
	beta.adminCall("partners/access", map[string]any{"domain": "alpha.e2e.test", "people": []string{"kamran"}}, nil, 200)

	env := proto.Envelope{ID: randomID(), From: aylin.address, FromDevice: aylin.id, FromCert: aylin.cert, To: kamran.address, ToDevice: kamran.id, Type: 2, Body: randomB64(64, 0)}
	good, _ := json.Marshal(map[string]any{"envelopes": []proto.Envelope{env}})

	// A verified organization that is not connected cannot deliver.
	if s := fedRaw(t, gamma, beta, "POST", "/fed/v1/deliver", good, nil); s != 403 {
		t.Fatalf("stranger delivery: %d", s)
	}
	// The connected partner can, once; the same signed request again is a replay.
	var replay *http.Request
	if s := fedRaw(t, alpha, beta, "POST", "/fed/v1/deliver", good, func(r *http.Request) { replay = r.Clone(context.Background()) }); s != 200 {
		t.Fatalf("delivery: %d", s)
	}
	replay.Body = io.NopCloser(bytes.NewReader(good))
	resp, err := l.client(nil).Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("replayed request: %d", resp.StatusCode)
	}
	// A body changed after signing.
	if s := fedRaw(t, alpha, beta, "POST", "/fed/v1/deliver", good, func(r *http.Request) {
		changed := bytes.Replace(good, []byte(env.Body), []byte(randomB64(64, 0)), 1)
		r.Body = io.NopCloser(bytes.NewReader(changed))
		r.ContentLength = int64(len(changed))
	}); s != 403 {
		t.Fatalf("altered body: %d", s)
	}
	// An old request, correctly signed an hour ago.
	alpha.srv.SetClock(func() time.Time { return time.Now().Add(-time.Hour) })
	old := fedRaw(t, alpha, beta, "POST", "/fed/v1/deliver", good, nil)
	alpha.srv.SetClock(time.Now)
	if s := old; s != 403 {
		t.Fatalf("old request: %d", s)
	}
	// A device certificate alpha did not sign: a sender pretending to be Aylin.
	forged := env
	forged.ID = randomID()
	_, fakeKey, _ := ed25519.GenerateKey(rand.Reader)
	proto.SignDevice(&forged.FromCert, fakeKey)
	bad, _ := json.Marshal(map[string]any{"envelopes": []proto.Envelope{forged}})
	if s := fedRaw(t, alpha, beta, "POST", "/fed/v1/deliver", bad, nil); s != 400 {
		t.Fatalf("forged certificate: %d", s)
	}
	// A sender outside the partner's domain.
	other := env
	other.ID, other.From = randomID(), "someone@gamma.e2e.test"
	bad, _ = json.Marshal(map[string]any{"envelopes": []proto.Envelope{other}})
	if s := fedRaw(t, alpha, beta, "POST", "/fed/v1/deliver", bad, nil); s != 400 {
		t.Fatalf("foreign sender: %d", s)
	}
	if n := len(kamran.inbox()); n != 1 {
		t.Fatalf("kamran has %d envelopes, want only the one genuine delivery", n)
	}
}

func TestDNSAloneCannotChangeAPartnersKey(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	connect(t, alpha, beta)

	// Someone who controls only beta's DNS publishes another key. The record
	// no longer matches beta's signed document, so nothing changes: alpha keeps
	// the pinned key and the impostor's key is never trusted.
	impostorPub, _, _ := ed25519.GenerateKey(rand.Reader)
	l.dns.SetTXT("_mohur.beta.e2e.test", proto.TXTValue(beta.server, impostorPub))
	alpha.srv.recheckPartners(context.Background())
	c, _ := alpha.st.Connection("beta.e2e.test")
	if c.State != store.Connected || c.Key != proto.B64(beta.key) {
		t.Fatalf("after a DNS-only change: state %s, key changed %v", c.State, c.Key != proto.B64(beta.key))
	}
	alpha.adminCall("partners/trust", map[string]any{"domain": "beta.e2e.test", "key": proto.B64(impostorPub)}, nil, 502)
}

func TestRebuiltPartnerIsPausedUntilAccepted(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	aylin := alpha.join(alpha.invite("aylin", "Aylin"), 200)
	connect(t, alpha, beta)

	// beta rebuilds its server: same domain and name, new organization key,
	// new record. Everything agrees, but alpha pinned the old key.
	rebuilt := l.start("beta.e2e.test")
	alpha.srv.recheckPartners(context.Background())
	c, _ := alpha.st.Connection("beta.e2e.test")
	if c.State != store.KeyChanged || c.NewKey != proto.B64(rebuilt.key) {
		t.Fatalf("after a verified key change: state %s", c.State)
	}
	// Nothing crosses while paused, in either direction.
	if s := fedRaw(t, rebuilt, alpha, "GET", "/fed/v1/directory", nil, nil); s != 403 {
		t.Fatalf("partner call while paused: %d", s)
	}
	aylin.call("GET", "/api/v1/keys?address=kamran@beta.e2e.test", nil, nil, 403)
	// A stale review is refused; the shown new key is accepted.
	alpha.adminCall("partners/trust", map[string]any{"domain": "beta.e2e.test", "key": proto.B64(beta.key)}, nil, 409)
	alpha.adminCall("partners/trust", map[string]any{"domain": "beta.e2e.test", "key": c.NewKey}, nil, 200)
	if s := fedRaw(t, rebuilt, alpha, "GET", "/fed/v1/directory", nil, nil); s != 200 {
		t.Fatalf("partner call after acceptance: %d", s)
	}
}

func TestDiscoveryRefusesRecordsThatDoNotAgree(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	_ = beta
	disc, _ := discover.New(discover.Config{Resolver: l.dns.Addr(), ExtraRoots: []*x509.Certificate{l.ca}, AllowPrivate: true})
	ctx := context.Background()
	if _, err := disc.Lookup(ctx, "beta.e2e.test"); err != nil {
		t.Fatalf("genuine lookup: %v", err)
	}
	cases := map[string][]string{
		"no record":          nil,
		"server elsewhere":   {proto.TXTValue(alpha.server, beta.key)},
		"key not the server": {proto.TXTValue(beta.server, alpha.key)},
		"two records":        {proto.TXTValue(beta.server, beta.key), proto.TXTValue(beta.server, beta.key)},
		"garbage":            {"v=mohur1 server=" + beta.server + " key=xyz"},
	}
	for name, txt := range cases {
		l.dns.SetTXT("_mohur.beta.e2e.test", txt...)
		if _, err := disc.Lookup(ctx, "beta.e2e.test"); err == nil {
			t.Errorf("%s: lookup succeeded", name)
		}
	}
	// Without AllowPrivate, a record pointing at loopback is refused.
	l.dns.SetTXT("_mohur.beta.e2e.test", proto.TXTValue(beta.server, beta.key))
	strict, _ := discover.New(discover.Config{Resolver: l.dns.Addr(), ExtraRoots: []*x509.Certificate{l.ca}})
	if _, err := strict.Lookup(ctx, "beta.e2e.test"); err == nil {
		t.Error("private address accepted without AllowPrivate")
	}
	// Without the lab CA, the certificate is not trusted.
	untrusting, _ := discover.New(discover.Config{Resolver: l.dns.Addr(), AllowPrivate: true})
	if _, err := untrusting.Lookup(ctx, "beta.e2e.test"); err == nil {
		t.Error("untrusted certificate accepted")
	}
	_ = fmt.Sprint()
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func TestStaleRequestIsNotConnectedWithAnotherKey(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	var res map[string]any
	beta.adminCall("partners/connect", map[string]any{"domain": "alpha.e2e.test"}, &res, 200)
	if c, _ := alpha.st.Connection("beta.e2e.test"); c.State != store.Incoming {
		t.Fatalf("alpha sees %s", c.State)
	}
	// beta rebuilds before alpha answers: its old request carries an old key.
	l.start("beta.e2e.test")
	alpha.adminCall("partners/accept", map[string]any{"domain": "beta.e2e.test"}, nil, 409)
	alpha.adminCall("partners/connect", map[string]any{"domain": "beta.e2e.test"}, nil, 409)
	c, _ := alpha.st.Connection("beta.e2e.test")
	if c.State != store.Incoming || c.Key != proto.B64(beta.key) {
		t.Fatalf("stale request became %s", c.State)
	}
	// Declining clears it; asking again works with the new key.
	alpha.adminCall("partners/remove", map[string]any{"domain": "beta.e2e.test"}, nil, 200)
	alpha.adminCall("partners/connect", map[string]any{"domain": "beta.e2e.test"}, &res, 200)
}
