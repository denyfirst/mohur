package autotls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/denyfirst/mohur/internal/store"
)

const name = "mohur.example.test"

// logBuf collects what a Manager logs.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitFor returns the first log line holding want.
func (l *logBuf) waitFor(t *testing.T, want string) string {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(l.String(), "\n") {
			if strings.Contains(line, want) {
				return line
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %q in the log:\n%s", want, l.String())
	return ""
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, filepath.Join(dir, "instance.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newManager(t *testing.T, ca *CAServer, st *store.Store, logs io.Writer) *Manager {
	t.Helper()
	m, err := New(Config{Name: name, Store: st, Log: slog.New(slog.NewTextHandler(logs, nil)),
		directory: ca.URL(), client: &http.Client{Timeout: 30 * time.Second}, waits: []time.Duration{time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// serve runs an HTTPS server with m's configuration and returns its address.
func serve(t *testing.T, m *Manager) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("mohur")) }),
		TLSConfig:         m.TLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slog.NewLogLogger(slog.DiscardHandler, slog.LevelDebug),
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func counts(ca *CAServer) (orders, certs int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return len(ca.orders), ca.certCount
}

// refused checks that a handshake naming sni gets no certificate. The client
// checks nothing itself, so only the server can refuse.
func refused(t *testing.T, addr, sni string) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err == nil {
		_ = conn.Close()
		t.Errorf("a handshake naming %q got a certificate", sni)
	}
}

var otherNames = []string{"", "other.example.test", "example.test", "mohur.example.test.evil.test", "www.mohur.example.test", "127.0.0.1"}

func TestACertificateIsGotForTheServerNameOnlyAndKept(t *testing.T) {
	ca := NewCAServer(t).ChallengeTypes("tls-alpn-01").Start()
	st := openStore(t)
	var logs logBuf
	m := newManager(t, ca, st, &logs)
	addr := serve(t, m)
	ca.Resolve(name, addr)

	// Names other than the server's are refused, and nothing is asked for them.
	for _, sni := range otherNames {
		refused(t, addr, sni)
	}
	if orders, _ := counts(ca); orders != 0 {
		t.Fatalf("other names made %d orders", orders)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	line := logs.waitFor(t, `msg="certificate ready"`)
	if !strings.Contains(line, "name="+name) || !strings.Contains(line, "until=") {
		t.Errorf("the log says %q", line)
	}
	cancel()
	<-done

	// A client that trusts the authority gets the certificate for the name,
	// and a page.
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: name, RootCAs: ca.Roots(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	_ = conn.Close()
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name {
		t.Fatalf("the certificate names %v", leaf.DNSNames)
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.Roots(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	resp, err := client.Get("https://" + name + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "mohur" {
		t.Fatalf("the page says %q", body)
	}

	// Still nothing for other names, and one certificate in all.
	for _, sni := range otherNames {
		refused(t, addr, sni)
	}
	if orders, certs := counts(ca); orders != 1 || certs != 1 {
		t.Fatalf("%d orders and %d certificates, want 1 and 1", orders, certs)
	}

	// It is kept in the store, and a restart serves it without asking again.
	if v, err := st.ACMEGet(name); err != nil || !bytes.Contains(v, []byte("PRIVATE KEY")) {
		t.Fatalf("the store holds %d bytes, %v", len(v), err)
	}
	again, err := newManager(t, ca, st, io.Discard).current()
	if err != nil {
		t.Fatal(err)
	}
	if again.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("a restart served another certificate")
	}
	if orders, certs := counts(ca); orders != 1 || certs != 1 {
		t.Fatalf("a restart asked again: %d orders, %d certificates", orders, certs)
	}
}

func TestManyOtherNamesAskForNothing(t *testing.T) {
	ca := NewCAServer(t).ChallengeTypes("tls-alpn-01").Start()
	m := newManager(t, ca, openStore(t), io.Discard)
	addr := serve(t, m)
	for i := range 30 {
		refused(t, addr, "n"+strings.Repeat("x", i)+".example.test")
	}
	if orders, certs := counts(ca); orders != 0 || certs != 0 {
		t.Fatalf("%d orders, %d certificates", orders, certs)
	}
}

func TestWhyThereIsNoCertificateIsSaidPlainly(t *testing.T) {
	ca := NewCAServer(t).ChallengeTypes("tls-alpn-01").Start()
	var logs logBuf
	m := newManager(t, ca, openStore(t), &logs)
	serve(t, m) // the authority is never told where: its check cannot connect

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	line := logs.waitFor(t, `msg="no certificate yet"`)
	for _, want := range []string{"name=" + name, "next=1h0m0s", `problem="`, `detail="`} {
		if !strings.Contains(line, want) {
			t.Errorf("no %s in %q", want, line)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if _, certs := counts(ca); certs != 0 {
		t.Fatalf("%d certificates", certs)
	}
}

func TestEachProblemIsExplained(t *testing.T) {
	authz := func(typ string) error {
		return &acme.AuthorizationError{Identifier: name, Errors: []error{
			&acme.Error{StatusCode: 400, ProblemType: "urn:ietf:params:acme:error:" + typ, Detail: "detail"}}}
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{authz("dns"), "does not point at an address"},
		{authz("caa"), "CAA record"},
		{authz("connection"), "could not connect to " + name + " on port 443"},
		{authz("unauthorized"), "Something other than this Mohur answered"},
		{authz("tls"), "Something other than this Mohur answered"},
		{authz("incorrectResponse"), "Something other than this Mohur answered"},
		{&acme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited"}, "limit for " + name},
		{&acme.Error{StatusCode: 400, ProblemType: "urn:ietf:params:acme:error:rejectedIdentifier"}, "does not issue"},
		{&url.Error{Op: "Post", URL: LetsEncrypt, Err: errUnreachable}, "could not reach Let's Encrypt"},
		{errors.New("acme/autocert: " + errUnreachable.Error()), "could not reach Let's Encrypt"},
		{errors.New("Post: dial tcp 192.0.2.1:443: i/o timeout"), "could not reach Let's Encrypt"},
		{errors.New("something else"), "did not issue a certificate for " + name},
	} {
		if got := Explain(name, c.err); !strings.Contains(got, c.want) {
			t.Errorf("%v: %q", c.err, got)
		}
	}
}

func TestOnlyAServerNameCanHaveACertificate(t *testing.T) {
	for _, good := range []string{"mohur.example.com", "chat.example.az", "xn--bcher-kva.example"} {
		if err := CheckName(good); err != nil {
			t.Errorf("%q refused", good)
		}
	}
	for _, bad := range []string{"", "example", "Mohur.example.com", "mohur.example.com.", "mohur.example.com:443",
		"*.example.com", "192.0.2.1", "::1", "[::1]", "mohur..example.com", "-mohur.example.com", "mohur_x.example.com",
		"bücher.example", "https://mohur.example.com", " mohur.example.com", "mohur.example.com/"} {
		if err := CheckName(bad); !errors.Is(err, ErrName) {
			t.Errorf("%q accepted", bad)
		}
		if _, err := New(Config{Name: bad, Store: openStore(t), Log: slog.New(slog.DiscardHandler)}); !errors.Is(err, ErrName) {
			t.Errorf("New(%q): %v", bad, err)
		}
	}
}

func TestLetsEncryptIsAskedOnlyAtPublicAddressesOnPort443(t *testing.T) {
	ips := func(s ...string) []net.IPAddr {
		var out []net.IPAddr
		for _, x := range s {
			out = append(out, net.IPAddr{IP: net.ParseIP(x)})
		}
		return out
	}
	var dialed []string
	d := publicDialer{
		lookup: func(_ context.Context, host string) ([]net.IPAddr, error) {
			switch host {
			case "inside.test":
				return ips("10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.1.2.3", "::1", "fd00::1", "fe80::1"), nil
			case "mixed.test":
				return ips("192.168.1.1", "1.1.1.1"), nil
			}
			return nil, errors.New("no such host")
		},
		dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return nil, errors.New("not dialled in tests")
		},
	}
	ctx := context.Background()
	for _, addr := range []string{"inside.test:443", "mixed.test:80", "mixed.test:8443", "mixed.test"} {
		if _, err := d.DialContext(ctx, "tcp", addr); !errors.Is(err, errUnreachable) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if len(dialed) != 0 {
		t.Fatalf("dialled %v", dialed)
	}
	_, _ = d.DialContext(ctx, "tcp", "mixed.test:443")
	if len(dialed) != 1 || dialed[0] != "1.1.1.1:443" {
		t.Fatalf("dialled %v, want the public address", dialed)
	}

	c := publicClient()
	if tr, ok := c.Transport.(*http.Transport); !ok || tr.Proxy != nil || tr.DialContext == nil {
		t.Fatal("the client may go through a proxy, or dials anywhere")
	}
	if c.CheckRedirect == nil || c.CheckRedirect(&http.Request{URL: &url.URL{Scheme: "https", Host: "acme-v02.api.letsencrypt.org"}}, nil) == nil {
		t.Fatal("the client follows redirects")
	}

	// A Manager given no client uses this one: an authority on this machine
	// is not even asked.
	m, err := New(Config{Name: name, Store: openStore(t), Log: slog.New(slog.DiscardHandler), directory: "https://127.0.0.1:1/directory"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.current(); err == nil || !strings.Contains(Explain(name, err), "could not reach Let's Encrypt") || !strings.Contains(err.Error(), errUnreachable.Error()) {
		t.Fatalf("an authority on this machine: %v", err)
	}
}

func TestTheConfigurationAnswersLetsEncryptsCheck(t *testing.T) {
	m, err := New(Config{Name: name, Store: openStore(t), Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	c := m.TLSConfig()
	if c.MinVersion != tls.VersionTLS12 || c.GetCertificate == nil {
		t.Fatal("the configuration has no minimum version or no certificate")
	}
	found := false
	for _, p := range c.NextProtos {
		found = found || p == acme.ALPNProto
	}
	if !found {
		t.Fatalf("protocols %v do not answer Let's Encrypt's check", c.NextProtos)
	}
}
