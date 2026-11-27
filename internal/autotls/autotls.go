// Package autotls gets the server's TLS certificate from Let's Encrypt and
// renews it, so an organization needs no certificate of its own: only a name
// that points at the server, and port 443 open to the internet.
//
// Let's Encrypt checks the name by connecting to it on port 443 (TLS-ALPN-01),
// and the server answers that itself, so nothing listens on port 80. A
// certificate is asked for the server's own name only, never for a name a
// client happens to send. The account key and what Let's Encrypt issues are
// kept in the database, sealed with the instance key.
package autotls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
)

// LetsEncrypt is where certificates come from.
const LetsEncrypt = acme.LetsEncryptURL

// Agreement is the Let's Encrypt Subscriber Agreement, which getting a
// certificate accepts.
const Agreement = "https://letsencrypt.org/repository/"

// ErrName means the name cannot have a certificate of its own.
var ErrName = errors.New("give the server's name, such as mohur.example.com, in lower case and without a port")

// errUnreachable means Let's Encrypt was not asked: its name led somewhere
// other than a public address on port 443.
var errUnreachable = errors.New("autotls: only public addresses on port 443 are asked")

// CheckName reports whether name can have a certificate: a DNS name of two
// labels or more, in lower case, with no port, trailing dot or wildcard.
func CheckName(name string) error {
	if d, err := proto.Domain(name); err != nil || d != name {
		return ErrName
	}
	return nil
}

// Store keeps the account key and the certificates; store.Store seals them
// with the instance key.
type Store interface {
	ACMEGet(name string) ([]byte, error)
	ACMEPut(name string, value []byte) error
	ACMEDelete(name string) error
}

// Config is what a Manager needs.
type Config struct {
	Name  string // the server's name, as CheckName accepts it
	Store Store
	Log   *slog.Logger

	// Tests only: another ACME directory and client, and shorter waits.
	directory string
	client    *http.Client
	waits     []time.Duration
}

// Manager serves the certificate and keeps it renewed.
type Manager struct {
	name  string
	m     *autocert.Manager
	log   *slog.Logger
	waits []time.Duration
}

// New returns a Manager for c.Name. Nothing is asked of Let's Encrypt until
// Run or the first connection.
func New(c Config) (*Manager, error) {
	if err := CheckName(c.Name); err != nil {
		return nil, err
	}
	if c.Store == nil || c.Log == nil {
		return nil, errors.New("autotls: a store and a log are needed")
	}
	dir, client, waits := c.directory, c.client, c.waits
	if dir == "" {
		dir = LetsEncrypt
	}
	if client == nil {
		client = publicClient()
	}
	if len(waits) == 0 {
		// Let's Encrypt allows five failed checks of a name an hour.
		waits = []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}
	}
	return &Manager{name: c.Name, log: c.Log, waits: waits, m: &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(c.Name),
		Cache:      cache{c.Store},
		Client:     &acme.Client{DirectoryURL: dir, HTTPClient: client},
	}}, nil
}

// TLSConfig serves the certificate and answers Let's Encrypt's check.
func (m *Manager) TLSConfig() *tls.Config {
	c := m.m.TLSConfig() // h2, http/1.1 and acme-tls/1
	c.MinVersion = tls.VersionTLS12
	return c
}

// Run gets the certificate as the server starts, so it is ready before anyone
// opens a page, and says plainly why when it cannot be had, trying again
// later. Once it is ready, Run looks daily that renewal keeps up.
func (m *Manager) Run(ctx context.Context) {
	var until time.Time
	failures := 0
	for {
		wait := 24 * time.Hour
		leaf, err := m.current()
		switch {
		case err != nil:
			wait = m.waits[min(failures, len(m.waits)-1)]
			failures++
			m.log.Warn("no certificate yet", "name", m.name, "next", wait, "problem", Explain(m.name, err), "detail", err.Error())
		case until.IsZero():
			failures = 0
			m.log.Info("certificate ready", "name", m.name, "until", leaf.NotAfter.UTC().Format(time.DateOnly))
		case !leaf.NotAfter.Equal(until):
			m.log.Info("certificate renewed", "name", m.name, "until", leaf.NotAfter.UTC().Format(time.DateOnly))
		}
		if err == nil {
			until = leaf.NotAfter
			// Renewal starts 30 days before the end; 20 left means it has
			// failed for ten days.
			if time.Until(until) < 20*24*time.Hour {
				m.log.Warn("certificate not renewed", "name", m.name, "until", until.UTC().Format(time.DateOnly),
					"problem", "Let's Encrypt has not renewed it. Check that "+m.name+" still points at this server and that port 443 is open.")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// current returns the certificate a modern client gets, getting it first if
// need be.
func (m *Manager) current() (*x509.Certificate, error) {
	c, err := m.m.GetCertificate(&tls.ClientHelloInfo{
		ServerName:       m.name,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		SupportedProtos:  []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// Explain says in plain words what stopped the certificate.
func Explain(name string, err error) string {
	s := err.Error()
	problem := func(t string) bool {
		return strings.Contains(s, "urn:ietf:params:acme:error:"+t+" ") || strings.Contains(s, "urn:ietf:params:acme:error:"+t+":")
	}
	var ue *url.Error
	switch {
	case problem("rateLimited"):
		return "Let's Encrypt's limit for " + name + " is reached for now. Mohur tries again later."
	case problem("caa"):
		return "A CAA record of " + name + " does not allow Let's Encrypt. Add letsencrypt.org to it, or remove it."
	case problem("dns"):
		return name + " does not point at an address. Add an A record for it, with this server's public address, at your DNS provider."
	case problem("connection"):
		return "Let's Encrypt could not connect to " + name + " on port 443. Check that the name points at this server and that port 443 is open to the internet."
	case problem("unauthorized"), problem("tls"), problem("incorrectResponse"):
		return "Something other than this Mohur answered for " + name + " on port 443: another server, or a proxy in front of this one."
	case problem("rejectedIdentifier"):
		return "Let's Encrypt does not issue certificates for " + name + "."
	case errors.Is(err, errUnreachable), errors.As(err, &ue), strings.Contains(s, errUnreachable.Error()), strings.Contains(s, "dial tcp"):
		return "This server could not reach Let's Encrypt. It needs to reach acme-v02.api.letsencrypt.org on port 443."
	default:
		return "Let's Encrypt did not issue a certificate for " + name + "."
	}
}

// cache keeps autocert's state in the store.
type cache struct{ st Store }

func (c cache) Get(_ context.Context, key string) ([]byte, error) {
	v, err := c.st.ACMEGet(key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	return v, err
}

func (c cache) Put(_ context.Context, key string, data []byte) error { return c.st.ACMEPut(key, data) }

func (c cache) Delete(_ context.Context, key string) error { return c.st.ACMEDelete(key) }

// publicDialer connects only to public addresses on port 443, whatever a name
// resolves to, so Let's Encrypt's name cannot be pointed at this server's own
// network.
type publicDialer struct {
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d publicDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "443" {
		return nil, errUnreachable
	}
	ips, err := d.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if discover.Public(ip.IP) {
			return d.dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}
	}
	return nil, errUnreachable
}

func publicClient() *http.Client {
	d := publicDialer{lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	return &http.Client{
		Timeout:       time.Minute,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// noRedirect refuses redirects: Let's Encrypt's API answers where it is asked.
func noRedirect(*http.Request, []*http.Request) error { return errUnreachable }
