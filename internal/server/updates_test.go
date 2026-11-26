package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/denyfirst/mohur/internal/sshsig/sshsigtest"
	"github.com/denyfirst/mohur/internal/updates"
)

// releaseHost stands in for GitHub's release downloads.
type releaseHost struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
}

func newReleaseHost(t *testing.T) *releaseHost {
	h := &releaseHost{files: map[string][]byte{}}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if b, ok := h.files[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *releaseHost) publish(priv ed25519.PrivateKey, sigFor []byte, name string) {
	sum := sha256.Sum256([]byte("build"))
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	if sigFor == nil {
		sigFor = sums
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files["/latest/download/SHA256SUMS"] = sums
	h.files["/latest/download/SHA256SUMS.sig"] = sshsigtest.Sign(priv, "file", sigFor)
}

type updateAnswer struct {
	Running   string `json:"running"`
	Latest    string `json:"latest"`
	Newer     bool   `json:"newer"`
	Daily     bool   `json:"daily"`
	Tampered  bool   `json:"tampered"`
	Error     string `json:"error"`
	Available bool   `json:"available"`
	Release   string `json:"release"`
	Command   string `json:"command"`
}

func TestAdminsCheckForUpdatesAndChooseTheDailyCheck(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	beta := l.start("beta.e2e.test")
	h := newReleaseHost(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h.publish(priv, nil, "mohurd_v0.2.0_linux_amd64")
	svc := &updates.Service{Checker: &updates.Checker{Client: h.srv.Client(), Base: h.srv.URL + "/", Key: sshsigtest.KeyText(pub)},
		Settings: alpha.st, Running: "v0.1.0"}
	alpha.srv.SetUpdates(svc)

	var st updateAnswer
	alpha.adminCall("updates", nil, &st, 200)
	if !st.Available || st.Running != "v0.1.0" || st.Latest != "" || st.Daily || st.Command != "sudo mohurd upgrade" {
		t.Fatalf("before any check: %+v", st)
	}
	var state map[string]any
	alpha.adminCall("state", nil, &state, 200)
	if _, ok := state["newerRelease"]; ok {
		t.Fatal("a newer release was announced before any check")
	}

	alpha.adminCall("updates/check", map[string]any{}, &st, 200)
	if st.Latest != "v0.2.0" || !st.Newer || st.Release != updates.Releases+"tag/v0.2.0" || st.Error != "" {
		t.Fatalf("after Check now: %+v", st)
	}
	alpha.adminCall("state", nil, &state, 200)
	if state["newerRelease"] != "v0.2.0" {
		t.Fatalf("every page should announce v0.2.0: %v", state["newerRelease"])
	}

	// The daily check is the admin's choice and survives in the store.
	alpha.adminCall("updates/daily", map[string]any{"daily": true}, &st, 200)
	if !st.Daily || !alpha.st.UpdatesDaily() {
		t.Fatalf("turned on: %+v, stored %v", st, alpha.st.UpdatesDaily())
	}
	alpha.adminCall("updates/daily", map[string]any{"daily": false}, &st, 200)
	if st.Daily || alpha.st.UpdatesDaily() {
		t.Fatal("turning it off did not hold")
	}
	for _, bad := range []any{map[string]any{}, map[string]any{"daily": "yes"}, map[string]any{"daily": true, "extra": 1}, []any{true}} {
		alpha.adminCall("updates/daily", bad, nil, 400)
	}
	if alpha.st.UpdatesDaily() {
		t.Fatal("a refused request turned the daily check on")
	}

	// A list that does not verify is a warning, never an update.
	h.publish(priv, []byte("another list"), "mohurd_v0.3.0_linux_amd64")
	svc.MinInterval = 1
	alpha.adminCall("updates/check", map[string]any{}, &st, 200)
	if !st.Tampered || st.Latest != "v0.2.0" {
		t.Fatalf("after a list that does not verify: %+v", st)
	}

	// Other sites and signed-out browsers get nothing.
	for _, path := range []string{"updates", "updates/check", "updates/daily"} {
		method := "POST"
		if path == "updates" {
			method = "GET"
		}
		req, _ := http.NewRequest(method, alpha.url("/admin/api/"+path), nil)
		req.Header.Set("Origin", "https://"+alpha.server)
		alpha.do(req, nil, 403)
		req, _ = http.NewRequest(method, alpha.url("/admin/api/"+path), nil)
		req.Header.Set("X-Mohur", "1")
		req.Header.Set("Origin", "https://evil.test")
		alpha.do(req, nil, 403)
		req, _ = http.NewRequest(method, alpha.url("/admin/api/"+path), nil)
		req.Header.Set("X-Mohur", "1")
		resp, err := l.client(nil).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("signed out %s: %d", path, resp.StatusCode)
		}
	}

	// A server without the service says so and asks no one.
	beta.adminCall("updates", nil, &st, 200)
	if st.Available {
		t.Fatal("beta has no update service")
	}
	beta.adminCall("updates/check", map[string]any{}, nil, 404)
	beta.adminCall("updates/daily", map[string]any{"daily": true}, nil, 404)
	if beta.st.UpdatesDaily() {
		t.Fatal("beta's daily check was turned on without a service")
	}
}
