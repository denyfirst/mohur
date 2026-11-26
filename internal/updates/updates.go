// Package updates says whether a newer signed release of Mohur exists, when an
// admin asks or once a day if they turned that on, and installs one only when
// the server's operator runs `mohurd upgrade`.
//
// # What a check does, and nothing else
//
// It asks GitHub for two public files of the latest release, SHA256SUMS and
// SHA256SUMS.sig, and checks the signature with denyfirst's release key,
// which is compiled into this binary (the key in .allowed_signers; a test
// holds the two equal). Only once the list verifies does it read the version
// from the file names on it. The request carries no cookie, no version and
// nothing about this server or its people. GitHub sees the server's address
// and that it asked, which is why the daily check is off until an admin turns
// it on, and why the page says so.
//
// A check never downloads a release and never changes anything. Upgrading is
// a command the operator runs as root; it checks the same signature and the
// file's hash before anything is replaced.
package updates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/sshsig"
)

// ReleaseKey is denyfirst's release signing key, the base64 field of the
// releases@denyfirst.dev line in .allowed_signers. Compiled in rather than
// fetched: a key fetched beside the files it vouches for vouches for nothing.
const ReleaseKey = "AAAAC3NzaC1lZDI1NTE5AAAAIDD7Ie9zRf76RynH052/Abkv5k2nzosQd2DihyQMixVR"

// Releases is where Mohur's releases are published.
const Releases = "https://github.com/denyfirst/mohur/releases/"

const (
	maxSums     = 16 << 10
	maxBinary   = 64 << 20
	timeout     = 30 * time.Second
	maxRedirect = 5
	userAgent   = "mohurd"
)

// allowedHosts are the only hosts a request may be redirected to.
var allowedHosts = map[string]bool{
	"github.com":                           true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// What a check can fail with. The page shows the message as written here;
// nothing a server sent is repeated.
var (
	ErrUnreachable = errors.New("GitHub could not be reached")
	ErrNotVerified = errors.New("the release list GitHub served does not verify with denyfirst's release key: do not update")
	ErrUnreadable  = errors.New("the release list could not be read")
)

// version is a release name: v, then three numbers of at most four digits.
var version = regexp.MustCompile(`^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$`)

// artifact is a release file whose name carries the version, matched whole.
var artifact = regexp.MustCompile(`^mohurd_(v\d{1,4}\.\d{1,4}\.\d{1,4})_linux_(amd64|arm64)$`)

// sumLine is one line of SHA256SUMS as sha256sum writes it.
var sumLine = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]{1,128})$`)

// Release is a release list whose signature verified.
type Release struct {
	Version string
	sums    map[string][32]byte
}

// Hash returns the SHA-256 the signed list gives for a file.
func (r Release) Hash(name string) ([32]byte, bool) {
	h, ok := r.sums[name]
	return h, ok
}

// BinaryName is the release file of mohurd for a processor.
func BinaryName(v, arch string) string { return "mohurd_" + v + "_linux_" + arch }

// Checker fetches and verifies release lists.
type Checker struct {
	// Client is used for every request. Nil builds one that reaches only
	// public addresses on port 443, follows GitHub's redirects alone and
	// trusts Roots.
	Client *http.Client

	// Roots judges GitHub's certificate. Nil means the system store.
	Roots *x509.CertPool

	// Base replaces Releases; tests point it elsewhere.
	Base string

	// Key replaces ReleaseKey; tests sign with their own.
	Key string

	once   sync.Once
	client *http.Client
}

func (c *Checker) base() string {
	if c.Base != "" {
		return c.Base
	}
	return Releases
}

func (c *Checker) http() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	c.once.Do(func() { c.client = newClient(c.Roots) })
	return c.client
}

// Latest returns the latest release's verified list.
func (c *Checker) Latest(ctx context.Context) (Release, error) {
	return c.list(ctx, c.base()+"latest/download/")
}

// File downloads one file of release v and returns it only if its SHA-256 is
// the one the verified list gives.
func (c *Checker) File(ctx context.Context, r Release, name string) ([]byte, error) {
	want, ok := r.Hash(name)
	if !ok {
		return nil, ErrUnreadable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	data, err := fetch(ctx, c.http(), c.base()+"download/"+r.Version+"/"+name, maxBinary)
	if err != nil {
		return nil, err
	}
	if sha256Sum(data) != want {
		return nil, ErrNotVerified
	}
	return data, nil
}

func (c *Checker) list(ctx context.Context, base string) (Release, error) {
	keyText := c.Key
	if keyText == "" {
		keyText = ReleaseKey
	}
	key, err := sshsig.ParseKey(keyText)
	if err != nil {
		return Release{}, ErrUnreadable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sums, err := fetch(ctx, c.http(), base+"SHA256SUMS", maxSums)
	if err != nil {
		return Release{}, err
	}
	sig, err := fetch(ctx, c.http(), base+"SHA256SUMS.sig", sshsig.MaxArmored)
	if err != nil {
		return Release{}, err
	}
	if sshsig.Verify(key, "file", sums, sig) != nil {
		return Release{}, ErrNotVerified
	}
	return ReadList(sums)
}

// ReadList reads a verified SHA256SUMS. Every Mohur file on it must name the
// same version, or the list is not read at all.
func ReadList(sums []byte) (Release, error) {
	r := Release{sums: map[string][32]byte{}}
	for _, line := range strings.Split(strings.TrimRight(string(sums), "\n"), "\n") {
		m := sumLine.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if m == nil {
			return Release{}, ErrUnreadable
		}
		var h [32]byte
		if _, err := hex.Decode(h[:], []byte(m[1])); err != nil {
			return Release{}, ErrUnreadable
		}
		if _, dup := r.sums[m[2]]; dup {
			return Release{}, ErrUnreadable
		}
		r.sums[m[2]] = h
		a := artifact.FindStringSubmatch(m[2])
		if a == nil {
			continue
		}
		if r.Version != "" && a[1] != r.Version {
			return Release{}, ErrUnreadable
		}
		r.Version = a[1]
	}
	if !version.MatchString(r.Version) {
		return Release{}, ErrUnreadable
	}
	return r, nil
}

// publicDialer connects only to public addresses on port 443, whatever a
// name resolves to, so a check cannot be pointed at this server's own network.
type publicDialer struct {
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d publicDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "443" {
		return nil, ErrUnreachable
	}
	ips, err := d.lookup(ctx, host)
	if err != nil {
		return nil, ErrUnreachable
	}
	for _, ip := range ips {
		if discover.Public(ip.IP) {
			return d.dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}
	}
	return nil, ErrUnreachable
}

func newClient(roots *x509.CertPool) *http.Client {
	d := publicDialer{lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	return &http.Client{
		Timeout:       10 * time.Minute,
		CheckRedirect: checkRedirect,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     5 * time.Second,
		},
	}
}

// checkRedirect follows GitHub's redirects and nothing else: HTTPS, to a host
// on the list, a few times at most.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirect || !allowedURL(req.URL) {
		return ErrUnreachable
	}
	return nil
}

func allowedURL(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && allowedHosts[strings.ToLower(u.Hostname())] &&
		(u.Port() == "" || u.Port() == "443")
}

// fetch reads one file, refusing anything over limit rather than cutting it.
func fetch(ctx context.Context, client *http.Client, raw string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, ErrUnreadable
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrUnreachable
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, limit+1)); err != nil {
		return nil, ErrUnreachable
	}
	if int64(buf.Len()) > limit {
		return nil, ErrUnreadable
	}
	return buf.Bytes(), nil
}

// IsRelease reports whether v is a release name, not a development build.
func IsRelease(v string) bool { return version.MatchString(v) }

// Newer reports whether latest is a later release than running. A running
// version that is not a release name is never behind: the page then shows
// the latest and claims nothing.
func Newer(running, latest string) bool {
	a, okA := parse(running)
	b, okB := parse(latest)
	if !okA || !okB {
		return false
	}
	for i := range a {
		if b[i] != a[i] {
			return b[i] > a[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	m := version.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Settings keeps whether to check daily.
type Settings interface {
	UpdatesDaily() bool
	SetUpdatesDaily(on bool) error
}

// State is what the admin page is told.
type State struct {
	Running   string `json:"running"`
	Latest    string `json:"latest,omitempty"`
	Newer     bool   `json:"newer"`
	CheckedAt int64  `json:"checkedAt,omitempty"`
	Daily     bool   `json:"daily"`
	Error     string `json:"error,omitempty"`
	// Tampered says the last list GitHub served did not verify. The page says
	// it as a warning, never as an update.
	Tampered bool `json:"tampered,omitempty"`
}

// Service holds what was last found, runs the daily check when it is on, and
// spaces checks apart however often somebody presses Check now.
type Service struct {
	Checker  *Checker
	Settings Settings
	Running  string

	// MinInterval is the least time between two checks; zero means a minute.
	MinInterval time.Duration
	// FirstWait and Interval replace the random wait before the first daily
	// check (one to ten minutes) and between checks (23 to 25 hours); tests
	// shorten them.
	FirstWait, Interval func() time.Duration
	// Now replaces the clock in tests.
	Now func() time.Time

	mu       sync.Mutex
	checking sync.Mutex
	state    State
	wake     chan struct{}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) wakeChan() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	return s.wake
}

// State returns what was last found.
func (s *Service) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state
	out.Running = s.Running
	out.Daily = s.Settings.UpdatesDaily()
	out.Newer = out.Latest != "" && Newer(s.Running, out.Latest)
	return out
}

// CheckNow checks, unless a check finished less than MinInterval ago, in
// which case it returns what that one found. Two at once wait for one.
func (s *Service) CheckNow(ctx context.Context) State {
	s.checking.Lock()
	defer s.checking.Unlock()
	min := s.MinInterval
	if min <= 0 {
		min = time.Minute
	}
	s.mu.Lock()
	recent := s.state.CheckedAt != 0 && s.now().Sub(time.Unix(s.state.CheckedAt, 0)) < min
	s.mu.Unlock()
	if !recent {
		r, err := s.Checker.Latest(ctx)
		s.mu.Lock()
		s.state.CheckedAt = s.now().Unix()
		if err != nil {
			// A list that does not verify says nothing about the latest
			// release, so what an earlier, verified check found is kept.
			s.state.Error = err.Error()
			s.state.Tampered = errors.Is(err, ErrNotVerified)
		} else {
			s.state.Error, s.state.Tampered, s.state.Latest = "", false, r.Version
		}
		s.mu.Unlock()
	}
	return s.State()
}

// SetDaily turns the daily check on or off and keeps the choice.
func (s *Service) SetDaily(on bool) error {
	if err := s.Settings.SetUpdatesDaily(on); err != nil {
		return err
	}
	select {
	case s.wakeChan() <- struct{}{}:
	default:
	}
	return nil
}

// Run checks about once a day while the daily check is on, until ctx ends,
// at a time no two servers share.
func (s *Service) Run(ctx context.Context) {
	first := s.FirstWait
	if first == nil {
		first = func() time.Duration { return between(time.Minute, 10*time.Minute) }
	}
	interval := s.Interval
	if interval == nil {
		interval = func() time.Duration { return 23*time.Hour + between(0, 2*time.Hour) }
	}
	wake := s.wakeChan()
	next := s.now().Add(first())
	for {
		var t *time.Timer
		var due <-chan time.Time
		if s.Settings.UpdatesDaily() {
			t = time.NewTimer(time.Until(next))
			due = t.C
		}
		select {
		case <-ctx.Done():
			if t != nil {
				t.Stop()
			}
			return
		case <-wake:
			if t != nil {
				t.Stop()
			}
			next = s.now().Add(first())
		case <-due:
			if s.Settings.UpdatesDaily() {
				s.CheckNow(ctx)
			}
			next = s.now().Add(interval())
		}
	}
}

// between is a random duration in [lo, hi), from crypto/rand.
func between(lo, hi time.Duration) time.Duration {
	span := hi - lo
	if span <= 0 {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return lo + span/2
	}
	return lo + time.Duration(n.Int64())
}
