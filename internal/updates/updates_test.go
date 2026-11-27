package updates

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/mohur/internal/sshsig/sshsigtest"
)

// host is a stand-in for GitHub's release downloads.
type host struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func newHost(t *testing.T) *host {
	h := &host{files: map[string][]byte{}, hits: map[string]int{}}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.hits[r.URL.Path]++
		body, ok := h.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *host) hit(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

func (h *host) set(path string, body []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[path] = body
}

func sumsFor(files map[string][]byte) []byte {
	var names []string
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, n := range names {
		h := sha256.Sum256(files[n])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	return []byte(b.String())
}

// publish puts a release on the host as the latest: its files, and their
// list signed by priv.
func (h *host) publish(priv ed25519.PrivateKey, version string, files map[string][]byte) []byte {
	sums := sumsFor(files)
	for n, body := range files {
		h.set("/download/"+version+"/"+n, body)
	}
	h.set("/latest/download/SHA256SUMS", sums)
	h.set("/latest/download/SHA256SUMS.sig", sshsigtest.Sign(priv, "file", sums))
	return sums
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func (h *host) checker(pub ed25519.PublicKey) *Checker {
	return &Checker{Client: h.srv.Client(), Base: h.srv.URL + "/", Key: sshsigtest.KeyText(pub)}
}

func TestALatestReleaseIsReadOnlyWhenItsListVerifies(t *testing.T) {
	h := newHost(t)
	pub, priv := newKey(t)
	c := h.checker(pub)
	ctx := context.Background()
	sums := h.publish(priv, "v0.2.0", map[string][]byte{
		"mohurd_v0.2.0_linux_amd64": []byte("amd64 build"), "mohurd_v0.2.0_linux_arm64": []byte("arm64 build"), "BUILD": []byte("notes"),
	})
	r, err := c.Latest(ctx)
	if err != nil || r.Version != "v0.2.0" {
		t.Fatalf("latest: %q, %v", r.Version, err)
	}
	if _, ok := r.Hash("mohurd_v0.2.0_linux_arm64"); !ok {
		t.Fatal("the arm64 build is missing from the list")
	}

	_, otherPriv := newKey(t)
	refused := []struct {
		name string
		sums []byte
		sig  []byte
		want error
	}{
		{"a list changed after signing", bytes.Replace(sums, []byte("  mohurd_v0.2.0_linux_amd64"), []byte("  mohurd_v0.2.0_linux_amd64\n"+strings.Repeat("0", 64)+"  mohurd_v0.2.0_linux_amd65"), 1), sshsigtest.Sign(priv, "file", sums), ErrNotVerified},
		{"a list signed by another key", sums, sshsigtest.Sign(otherPriv, "file", sums), ErrNotVerified},
		{"a signature for another namespace", sums, sshsigtest.Sign(priv, "git", sums), ErrNotVerified},
		{"no signature", sums, nil, ErrUnreachable},
		{"two versions in one list", sumsFor(map[string][]byte{"mohurd_v0.2.0_linux_amd64": {1}, "mohurd_v0.3.0_linux_arm64": {2}}), nil, ErrUnreadable},
		{"no mohurd build", sumsFor(map[string][]byte{"BUILD": {1}}), nil, ErrUnreadable},
		{"a version name too long", sumsFor(map[string][]byte{"mohurd_v12345.0.0_linux_amd64": {1}}), nil, ErrUnreadable},
		{"a malformed line", []byte("abc  mohurd_v0.2.0_linux_amd64\n"), nil, ErrUnreadable},
		{"the same name twice", []byte(strings.Repeat(strings.Repeat("a", 64)+"  mohurd_v0.2.0_linux_amd64\n", 2)), nil, ErrUnreadable},
		{"a list too long", bytes.Repeat([]byte(strings.Repeat("a", 64)+"  x\n"), 300), nil, ErrUnreadable},
	}
	for _, tc := range refused {
		h.set("/latest/download/SHA256SUMS", tc.sums)
		sig := tc.sig
		if sig == nil && tc.want != ErrUnreachable {
			sig = sshsigtest.Sign(priv, "file", tc.sums)
		}
		if sig == nil {
			h.mu.Lock()
			delete(h.files, "/latest/download/SHA256SUMS.sig")
			h.mu.Unlock()
		} else {
			h.set("/latest/download/SHA256SUMS.sig", sig)
		}
		if _, err := c.Latest(ctx); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestTheReleaseKeyIsDenyfirstsKeyInAllowedSigners(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "releases@denyfirst.dev" && f[1] == `namespaces="file"` && f[2] == "ssh-ed25519" {
			if f[3] != ReleaseKey {
				t.Fatalf("the compiled-in key differs from .allowed_signers")
			}
			return
		}
	}
	t.Fatal(".allowed_signers has no releases@denyfirst.dev line for files")
}

func TestNewerComparesReleaseNamesOnly(t *testing.T) {
	for _, tc := range []struct {
		running, latest string
		want            bool
	}{
		{"v0.1.0", "v0.2.0", true}, {"v0.1.9", "v0.1.10", true}, {"v0.9.9", "v1.0.0", true},
		{"v0.2.0", "v0.2.0", false}, {"v0.3.0", "v0.2.0", false}, {"dev", "v0.2.0", false},
		{"v0.1.0", "v0.2", false}, {"v0.1.0", "0.2.0", false}, {"v0.1.0", "v0.2.0-rc1", false},
	} {
		if got := Newer(tc.running, tc.latest); got != tc.want {
			t.Errorf("Newer(%q, %q) = %v", tc.running, tc.latest, got)
		}
	}
}

func TestRequestsStayOnGitHub(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://github.com/denyfirst/mohur/releases/latest/download/SHA256SUMS": true,
		"https://objects.githubusercontent.com/x":                                true,
		"https://release-assets.githubusercontent.com/x":                         true,
		"https://GitHub.com:443/x":                                               true,
		"http://github.com/x":                                                    false,
		"https://github.com:8443/x":                                              false,
		"https://evil.example/x":                                                 false,
		"https://github.com.evil.example/x":                                      false,
		"https://user@github.com/x":                                              false,
	} {
		u, _ := url.Parse(raw)
		if allowedURL(u) != want {
			t.Errorf("%s: allowed = %v", raw, !want)
		}
	}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "github.com"}}
	if checkRedirect(req, make([]*http.Request, maxRedirect)) == nil {
		t.Fatal("redirects are not limited")
	}
	// The real client refuses private addresses and other ports outright.
	c := &Checker{Base: "https://127.0.0.1/", Key: ReleaseKey}
	if _, err := c.Latest(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("a loopback base: %v", err)
	}
}

func TestChecksReachOnlyPublicAddressesOnPort443(t *testing.T) {
	var dialed []string
	d := publicDialer{dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("not dialing in a test")
	}}
	answer := func(ips ...string) func(context.Context, string) ([]net.IPAddr, error) {
		return func(context.Context, string) ([]net.IPAddr, error) {
			var out []net.IPAddr
			for _, ip := range ips {
				out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
			}
			return out, nil
		}
	}
	for _, private := range [][]string{{"127.0.0.1"}, {"10.0.0.7", "192.168.1.1"}, {"::1"}, {"169.254.169.254"}, {"100.64.0.1"}, {"0.0.0.0"}, {"fe80::1"}, {"fd00::1"}} {
		d.lookup = answer(private...)
		if _, err := d.DialContext(context.Background(), "tcp", "github.com:443"); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("%v: %v", private, err)
		}
	}
	if len(dialed) != 0 {
		t.Fatalf("dialed private addresses: %v", dialed)
	}
	d.lookup = answer("10.0.0.7", "140.82.121.4")
	_, _ = d.DialContext(context.Background(), "tcp", "github.com:443")
	if len(dialed) != 1 || dialed[0] != "140.82.121.4:443" {
		t.Fatalf("dialed %v, want only the public address", dialed)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "github.com:8443"); !errors.Is(err, ErrUnreachable) || len(dialed) != 1 {
		t.Fatalf("another port: %v, dialed %v", err, dialed)
	}
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("no such host") }
	if _, err := d.DialContext(context.Background(), "tcp", "github.com:443"); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("a failed lookup: %v", err)
	}
}

type memSettings struct {
	mu sync.Mutex
	on bool
}

func (m *memSettings) UpdatesDaily() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.on }
func (m *memSettings) SetUpdatesDaily(on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.on = on
	return nil
}

func TestCheckNowIsSpacedAndKeepsTheLastVerifiedAnswer(t *testing.T) {
	h := newHost(t)
	pub, priv := newKey(t)
	h.publish(priv, "v0.2.0", map[string][]byte{"mohurd_v0.2.0_linux_amd64": {1}})
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	s := &Service{Checker: h.checker(pub), Settings: &memSettings{}, Running: "v0.1.0", Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	ctx := context.Background()
	st := s.CheckNow(ctx)
	if st.Latest != "v0.2.0" || !st.Newer || st.Daily || st.CheckedAt != now.Unix() || st.Error != "" {
		t.Fatalf("first check: %+v", st)
	}
	// Pressing again within the minute asks GitHub nothing.
	s.CheckNow(ctx)
	if n := h.hit("/latest/download/SHA256SUMS"); n != 1 {
		t.Fatalf("GitHub was asked %d times within a minute", n)
	}
	// A list that does not verify is a warning, and the verified answer stays.
	h.set("/latest/download/SHA256SUMS.sig", sshsigtest.Sign(priv, "file", []byte("something else")))
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	st = s.CheckNow(ctx)
	if !st.Tampered || st.Latest != "v0.2.0" || !strings.Contains(st.Error, "do not update") {
		t.Fatalf("after a bad list: %+v", st)
	}
	// A development build is never told it is behind.
	s.Running = "dev"
	if s.State().Newer {
		t.Fatal("a development build was told to update")
	}
}

func TestTheDailyCheckRunsOnlyWhileItIsOn(t *testing.T) {
	h := newHost(t)
	pub, priv := newKey(t)
	h.publish(priv, "v0.2.0", map[string][]byte{"mohurd_v0.2.0_linux_amd64": {1}})
	settings := &memSettings{}
	tick := func() time.Duration { return 5 * time.Millisecond }
	s := &Service{Checker: h.checker(pub), Settings: settings, Running: "v0.1.0", MinInterval: time.Nanosecond, FirstWait: tick, Interval: tick}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	asked := func() int { return h.hit("/latest/download/SHA256SUMS") }

	time.Sleep(100 * time.Millisecond)
	if n := asked(); n != 0 {
		t.Fatalf("off by default, yet GitHub was asked %d times", n)
	}
	if err := s.SetDaily(true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for asked() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if asked() < 2 {
		t.Fatal("turned on, the daily check did not run")
	}
	if err := s.SetDaily(false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	before := asked()
	time.Sleep(100 * time.Millisecond)
	if after := asked(); after != before {
		t.Fatalf("turned off, GitHub was still asked (%d then %d)", before, after)
	}
}

// upgrade is one upgrade's stand-ins: the binary, the services and the log
// of what was restarted.
type upgrade struct {
	exe       string
	restarted []string
	active    bool
	units     []string
}

func newUpgrade(t *testing.T) *upgrade {
	exe := filepath.Join(t.TempDir(), "mohurd")
	if err := os.WriteFile(exe, []byte("old build"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &upgrade{exe: exe, active: true, units: []string{"mohurd.service", "mohurd-gamma.service"}}
}

func (u *upgrade) run(c *Checker, running, arch string) error {
	up := &Upgrader{Checker: c, Running: running, Exe: u.exe, Arch: arch, Settle: time.Millisecond,
		Units:   func() ([]string, error) { return u.units, nil },
		Restart: func(unit string) error { u.restarted = append(u.restarted, unit); return nil },
		Active:  func(string) bool { return u.active }}
	return up.Run(context.Background())
}

func (u *upgrade) binary(t *testing.T) string {
	b, err := os.ReadFile(u.exe)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUpgradeInstallsOnlyAVerifiedNewerBuild(t *testing.T) {
	h := newHost(t)
	pub, priv := newKey(t)
	h.publish(priv, "v0.2.0", map[string][]byte{"mohurd_v0.2.0_linux_amd64": []byte("new build"), "mohurd_v0.2.0_linux_arm64": []byte("arm build")})
	c := h.checker(pub)

	u := newUpgrade(t)
	if err := u.run(c, "v0.1.0", "amd64"); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.ReadFile(u.exe + ".previous")
	if u.binary(t) != "new build" || string(prev) != "old build" || !slices.Equal(u.restarted, u.units) {
		t.Fatalf("binary %q, previous %q, restarted %v", u.binary(t), prev, u.restarted)
	}
	if _, err := os.Stat(u.exe + ".new"); !os.IsNotExist(err) {
		t.Fatal("the download was left beside the binary")
	}

	// The same or a later version running: nothing is downloaded or touched.
	for _, running := range []string{"v0.2.0", "v0.3.0"} {
		u := newUpgrade(t)
		if err := u.run(c, running, "amd64"); !errors.Is(err, ErrUpToDate) || u.binary(t) != "old build" || len(u.restarted) != 0 {
			t.Fatalf("running %s: %v, %q, %v", running, err, u.binary(t), u.restarted)
		}
	}
	if n := h.hit("/download/v0.2.0/mohurd_v0.2.0_linux_amd64"); n != 1 {
		t.Fatalf("the build was downloaded %d times", n)
	}
	// A development build takes the release.
	u = newUpgrade(t)
	if err := u.run(c, "dev", "arm64"); err != nil || u.binary(t) != "arm build" {
		t.Fatalf("from a development build: %v, %q", err, u.binary(t))
	}
	// No running service: installed, nothing restarted.
	u = newUpgrade(t)
	u.units = nil
	if err := u.run(c, "v0.1.0", "amd64"); err != nil || u.binary(t) != "new build" || len(u.restarted) != 0 {
		t.Fatalf("without a service: %v, %q, %v", err, u.binary(t), u.restarted)
	}
}

func TestUpgradeRefusesAnythingItCannotVerify(t *testing.T) {
	h := newHost(t)
	pub, priv := newKey(t)
	_, otherPriv := newKey(t)
	good := map[string][]byte{"mohurd_v0.2.0_linux_amd64": []byte("new build")}
	cases := []struct {
		name  string
		setup func()
		arch  string
		units []string
		want  error
	}{
		{"a build that differs from the signed list", func() {
			h.publish(priv, "v0.2.0", good)
			h.set("/download/v0.2.0/mohurd_v0.2.0_linux_amd64", []byte("swapped build"))
		}, "amd64", nil, ErrNotVerified},
		{"a list signed by another key", func() { h.publish(otherPriv, "v0.2.0", good) }, "amd64", nil, ErrNotVerified},
		{"no build for this processor", func() { h.publish(priv, "v0.2.0", good) }, "riscv64", nil, nil},
		{"a build too large", func() {
			h.publish(priv, "v0.2.0", map[string][]byte{"mohurd_v0.2.0_linux_amd64": make([]byte, maxBinary+1)})
		}, "amd64", nil, ErrUnreadable},
		{"a unit that is not mohurd", func() { h.publish(priv, "v0.2.0", good) }, "amd64", []string{"sshd.service"}, nil},
		{"a unit name with a path", func() { h.publish(priv, "v0.2.0", good) }, "amd64", []string{"mohurd-../x.service"}, nil},
	}
	for _, tc := range cases {
		tc.setup()
		u := newUpgrade(t)
		if tc.units != nil {
			u.units = tc.units
		}
		err := u.run(h.checker(pub), "v0.1.0", tc.arch)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if u.binary(t) != "old build" || len(u.restarted) != 0 {
			t.Errorf("%s: binary %q, restarted %v", tc.name, u.binary(t), u.restarted)
		}
		if _, err := os.Stat(u.exe + ".new"); !os.IsNotExist(err) {
			t.Errorf("%s: a partial download was left", tc.name)
		}
	}
}

func TestAnUpgradeThatDoesNotStartIsRolledBack(t *testing.T) {
	h := newHost(t)
	pub, priv := newKey(t)
	h.publish(priv, "v0.2.0", map[string][]byte{"mohurd_v0.2.0_linux_amd64": []byte("broken build")})
	u := newUpgrade(t)
	u.active = false
	err := u.run(h.checker(pub), "v0.1.0", "amd64")
	if err == nil || !strings.Contains(err.Error(), "previous version is back") {
		t.Fatalf("a build that did not start: %v", err)
	}
	if u.binary(t) != "old build" {
		t.Fatalf("the old binary is not back: %q", u.binary(t))
	}
	if len(u.restarted) != 4 {
		t.Fatalf("restarted %v, want each unit twice (new, then old)", u.restarted)
	}
}
