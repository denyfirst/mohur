package server

import (
	"bytes"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/mohur/internal/store"
)

type resetStartAnswer struct {
	Admin string   `json:"admin"`
	Seed  string   `json:"seed"`
	QR    []string `json:"qr"`
}

type failAnswer struct {
	Error string `json:"error"`
}

// browser is another browser on the organization's admin pages, signed out.
func (o *org) browser() *org {
	jar, _ := cookiejar.New(nil)
	b := *o
	b.admin = o.lab.client(jar)
	return &b
}

func TestResetLetsTheAdminBackIn(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	alpha.adminCall("people", nil, nil, 200) // the admin is signed in from setup
	away := alpha.browser()

	code, err := store.ResetCode(alpha.keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Cross-site and malformed calls are refused before the code is looked at.
	req, _ := http.NewRequest("POST", away.url("/admin/api/reset/start"), bytes.NewReader([]byte(`{"code":"`+code+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+away.server)
	away.do(req, nil, 403) // no X-Mohur header
	req, _ = http.NewRequest("POST", away.url("/admin/api/reset/start"), bytes.NewReader([]byte(`{"code":"`+code+`"}`)))
	req.Header.Set("X-Mohur", "1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.e2e.test")
	away.do(req, nil, 403)
	req, _ = http.NewRequest("POST", away.url("/admin/api/reset/start"), bytes.NewReader([]byte(`{"code":"`+code+`"}`)))
	req.Header.Set("X-Mohur", "1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	away.do(req, nil, 403)
	away.adminCall("reset/start", "not an object", nil, 403)

	var bad failAnswer
	away.adminCall("reset/start", map[string]any{"code": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"}, &bad, 403)
	if !strings.Contains(bad.Error, "sudo mohurd reset-admin") {
		t.Fatalf("a wrong code does not say what to do: %q", bad.Error)
	}
	// Finishing without starting is refused even with a good code.
	away.adminCall("reset/finish", map[string]any{"code": code, "username": "admin", "password": "a brand new admin password", "totp": "123456"}, nil, 403)

	var start resetStartAnswer
	away.adminCall("reset/start", map[string]any{"code": strings.ToLower(code)}, &start, 200)
	if start.Admin != "admin" || len(start.Seed) != 32 || len(start.QR) == 0 {
		t.Fatalf("reset start: %+v", start)
	}
	in := map[string]any{"code": code, "username": "admin", "password": "short", "totp": store.TOTP(start.Seed, time.Now())}
	away.adminCall("reset/finish", in, nil, 400)
	in["password"] = "a brand new admin password"
	in["totp"] = wrongTOTP(start.Seed)
	away.adminCall("reset/finish", in, nil, 403)
	in["username"] = "nobody"
	in["totp"] = store.TOTP(start.Seed, time.Now())
	away.adminCall("reset/finish", in, &bad, 403)
	if !strings.Contains(bad.Error, "reset code") {
		t.Fatalf("an unknown admin: %q", bad.Error)
	}

	in["username"] = "admin"
	var done struct {
		Admin    string   `json:"admin"`
		Recovery []string `json:"recovery"`
	}
	away.adminCall("reset/finish", in, &done, 200)
	if done.Admin != "admin" || len(done.Recovery) != 10 {
		t.Fatalf("reset finish: %+v", done)
	}
	// This browser is signed in; the admin's other sessions are over.
	away.adminCall("people", nil, nil, 200)
	alpha.adminCall("people", nil, nil, 401)
	// The code is spent.
	away.browser().adminCall("reset/start", map[string]any{"code": code}, nil, 403)

	// The old password no longer signs in; the new one does.
	other := alpha.browser()
	other.adminCall("signin", map[string]any{"username": "admin", "password": "correct horse battery staple", "code": done.Recovery[0]}, nil, 401)
	other.adminCall("signin", map[string]any{"username": "admin", "password": "a brand new admin password", "code": done.Recovery[1]}, nil, 200)
	other.adminCall("people", nil, nil, 200)
}

func TestResetAttemptsAreLimited(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	now := time.Now()
	alpha.srv.SetClock(func() time.Time { return now })
	away := alpha.browser()
	for range 10 {
		away.adminCall("reset/start", map[string]any{"code": store.RandomCode(15)}, nil, 403)
	}
	code, err := store.ResetCode(alpha.keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var refused failAnswer
	away.adminCall("reset/start", map[string]any{"code": code}, &refused, 403)
	if !strings.Contains(refused.Error, "Wait a minute") {
		t.Fatalf("the eleventh attempt in a minute: %q", refused.Error)
	}
	now = now.Add(time.Minute)
	away.adminCall("reset/start", map[string]any{"code": code}, nil, 200)
}

// wrongTOTP returns a six-digit code the seed does not show now or around now.
func wrongTOTP(seed string) string {
	now := time.Now()
	near := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		near[store.TOTP(seed, now.Add(d))] = true
	}
	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if !near[c] {
			return c
		}
	}
	return "444444"
}
