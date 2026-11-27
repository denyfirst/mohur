// Package discover finds and verifies another Mohur organization from its
// domain alone. It trusts an organization only when three independent things
// name the same key: the domain's _mohur TXT record, a TLS certificate for a
// server under that domain, and the organization document that key signed.
package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
)

// Errors a person can act on. Every other failure is ErrUnreachable.
var (
	ErrNoRecord    = errors.New("the domain has no valid Mohur DNS record")
	ErrUnreachable = errors.New("the organization's server could not be reached securely")
	ErrMismatch    = errors.New("the server's signed details do not match the domain's DNS record")
)

// Config says how to reach other organizations.
type Config struct {
	// Resolver is a DNS server address (host:port) to use instead of the
	// system's; empty uses the system resolver.
	Resolver string
	// ExtraRoots adds certificate authorities to the system's, for private CAs.
	ExtraRoots []*x509.Certificate
	// AllowPrivate permits partner servers on private and loopback addresses.
	// Without it, discovery refuses them, so a stranger's DNS record cannot
	// make this server open connections inside its own network.
	AllowPrivate bool
}

// Verifier performs discovery and makes the HTTP client used for federation.
type Verifier struct {
	resolver *net.Resolver
	client   *http.Client
}

// New builds a Verifier.
func New(cfg Config) (*Verifier, error) {
	resolver := net.DefaultResolver
	if cfg.Resolver != "" {
		addr := cfg.Resolver
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, c := range cfg.ExtraRoots {
		roots.AddCert(c)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: resolver, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("refusing unresolved address")
		}
		if !cfg.AllowPrivate && !public(ip) {
			return fmt.Errorf("refusing private address %s", ip)
		}
		return nil
	}}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &Verifier{resolver: resolver, client: client}, nil
}

// ParseRoots reads PEM certificates for Config.ExtraRoots.
func ParseRoots(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}
	return certs, nil
}

// Public reports whether ip is an ordinary internet address: not loopback,
// private, link-local, shared or unspecified.
func Public(ip net.IP) bool { return public(ip) }

func public(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		// 100.64.0.0/10 carrier-grade NAT and 0.0.0.0/8 are not reachable public hosts either.
		(ip.To4() != nil && (ip.To4()[0] == 100 && ip.To4()[1]&0xc0 == 64 || ip.To4()[0] == 0)))
}

// Client is the HTTP client for talking to partner servers.
func (v *Verifier) Client() *http.Client { return v.client }

// TXT reads and parses the domain's _mohur record.
func (v *Verifier) TXT(ctx context.Context, domain string) (proto.TXT, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	records, err := v.resolver.LookupTXT(ctx, "_mohur."+domain)
	if err != nil {
		return proto.TXT{}, ErrNoRecord
	}
	t, err := proto.ParseTXT(records, domain)
	if err != nil {
		return proto.TXT{}, ErrNoRecord
	}
	return t, nil
}

// Document fetches a server's signed organization document over verified TLS.
func (v *Verifier) Document(ctx context.Context, server string) (proto.OrgDoc, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+server+"/.well-known/mohur", nil)
	if err != nil {
		return proto.OrgDoc{}, ErrUnreachable
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return proto.OrgDoc{}, ErrUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proto.OrgDoc{}, ErrUnreachable
	}
	var d proto.OrgDoc
	dec := json.NewDecoder(io.LimitReader(resp.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return proto.OrgDoc{}, ErrUnreachable
	}
	return d, nil
}

// Lookup verifies an organization from its domain and returns its document.
func (v *Verifier) Lookup(ctx context.Context, domain string) (proto.OrgDoc, error) {
	t, err := v.TXT(ctx, domain)
	if err != nil {
		return proto.OrgDoc{}, err
	}
	d, err := v.Document(ctx, t.Server)
	if err != nil {
		return proto.OrgDoc{}, err
	}
	key, err := d.Check()
	if err != nil || d.Domain != domain || d.Server != t.Server || !key.Equal(t.Key) {
		return proto.OrgDoc{}, ErrMismatch
	}
	return d, nil
}
