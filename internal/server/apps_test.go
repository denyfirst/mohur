package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/denyfirst/mohur/internal/proto"
)

func TestAppVersionsCompareAsNumbers(t *testing.T) {
	for _, v := range []string{"0.1.0", "0.0.0", "10.20.30", "9999.9999.9999"} {
		if _, ok := parseApp(v); !ok {
			t.Errorf("%q refused", v)
		}
	}
	for _, v := range []string{"", "v0.1.0", "0.1", "0.1.0.0", "00.1.0", "0.01.0", "0.1.0-beta", "0.1.0 ", " 0.1.0",
		"10000.0.0", "0.1.0\n", "a.b.c", "0.1.0,0.2.0", "+1.0.0", "-1.0.0", "١.٢.٣"} {
		if _, ok := parseApp(v); ok {
			t.Errorf("%q accepted", v)
		}
	}
	for _, c := range []struct {
		a, b  string
		older bool
	}{
		{"0.1.0", "0.1.0", false}, {"0.1.0", "0.1.1", true}, {"0.1.1", "0.1.0", false},
		{"0.9.0", "0.10.0", true}, {"0.10.0", "0.9.0", false}, {"9.0.0", "10.0.0", true},
		{"1.0.0", "0.99.99", false}, {"0.2.0", "1.0.0", true}, {"2.0.0", "1.9999.9999", false},
	} {
		if got := appOlder(c.a, c.b); got != c.older {
			t.Errorf("appOlder(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

// app is the version the People page shows for a person.
func (o *org) app(username string) string {
	o.lab.t.Helper()
	var people []personView
	o.adminCall("people", nil, &people, 200)
	for _, p := range people {
		if p.Username == username {
			return p.App
		}
	}
	return "missing"
}

// sessionWith signs d in once, giving each of apps as a version header (none
// for nil), and signing with another key when forged.
func (d *device) sessionWith(apps []string, forged bool) (int, string) {
	t := d.org.lab.t
	t.Helper()
	var ch struct {
		Nonce string `json:"nonce"`
	}
	d.call("POST", "/api/v1/session/challenge", map[string]any{"address": d.address, "device": d.id}, &ch, 200)
	key := d.auth
	if forged {
		_, key, _ = ed25519.GenerateKey(rand.Reader)
	}
	sig := proto.Sign(key, proto.ContextSession, d.org.domain, d.address, strconv.Itoa(int(d.id)), ch.Nonce)
	b, _ := json.Marshal(map[string]any{"address": d.address, "device": d.id, "nonce": ch.Nonce, "sig": sig})
	req, _ := http.NewRequest("POST", d.org.url("/api/v1/session"), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, a := range apps {
		req.Header.Add(AppHeader, a)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// Admins see which app each person runs. Colleagues and partners never do.
func TestAdminsSeeEachAppsVersionAndNoOneElseDoes(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	connect(t, alpha, beta)
	aylin := alpha.joinAs(alpha.inviteFor("aylin", "Aylin", beta.domain), "3.14.15", 200)
	murad := alpha.joinAs(alpha.invite("murad", "Murad"), "2.0.0", 200)
	kamran := beta.join(beta.inviteFor("kamran", "Kamran", alpha.domain), 200)
	if got := alpha.app("aylin"); got != "3.14.15" {
		t.Fatalf("after joining the People page shows %q", got)
	}
	if got := alpha.app("murad"); got != "2.0.0" {
		t.Fatalf("murad: %q", got)
	}

	// Signing in again records an updated app.
	aylin.app = "3.14.16"
	aylin.signIn(200)
	if got := alpha.app("aylin"); got != "3.14.16" {
		t.Fatalf("after an update the People page shows %q", got)
	}

	// Only a device that proves its key records a version, and only a well
	// formed, single one.
	if code, _ := aylin.sessionWith([]string{"9.9.9"}, true); code != 401 {
		t.Fatalf("a forged sign-in answered %d", code)
	}
	for _, bad := range [][]string{{"v3.14.17"}, {"3.14"}, {"03.14.17"}, {"3.14.17-beta"}, {"12345.0.0"},
		{"3.14.17,3.14.18"}, {""}, {"3.14.17", "3.14.17"}, {"3.14.17", "9.9.9"}} {
		if code, _ := aylin.sessionWith(bad, false); code != 400 {
			t.Fatalf("version %q answered %d", bad, code)
		}
	}
	if got := alpha.app("aylin"); got != "3.14.16" {
		t.Fatalf("a refused sign-in changed the version to %q", got)
	}
	// An app that gives no version is too old for this server.
	code, body := aylin.sessionWith(nil, false)
	if code != http.StatusUpgradeRequired || !strings.Contains(body, "Update Mohur to "+OldestApp+" or newer") {
		t.Fatalf("no version: %d %s", code, body)
	}

	// Colleagues and partners get names and certificates, not versions.
	var raw json.RawMessage
	for who, d := range map[string]*device{"a colleague": murad, "a partner": kamran} {
		d.call("GET", "/api/v1/contacts?fresh=1", nil, &raw, 200)
		s := string(raw)
		if !strings.Contains(s, "aylin@alpha.e2e.test") {
			t.Fatalf("%s does not see aylin at all: %s", who, s)
		}
		if strings.Contains(s, "3.14.1") || strings.Contains(s, "2.0.0") || strings.Contains(s, `"app"`) {
			t.Fatalf("%s sees app versions: %s", who, s)
		}
	}
	if dir, _, err := beta.st.Directory(alpha.domain); err != nil || len(dir) == 0 {
		t.Fatalf("beta holds no directory of alpha: %v", err)
	} else if b, _ := json.Marshal(dir); bytes.Contains(b, []byte("3.14.1")) {
		t.Fatalf("beta's copy of alpha's people holds versions: %s", b)
	}
}

// When this server needs a newer app, an older one is told to update, on
// joining and on signing in, and its invite is not spent.
func TestOldAppsAreAskedToUpdate(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	alpha.srv.setOldestApp("3.15.0")
	var st updateAnswer
	alpha.adminCall("updates", nil, &st, 200)
	if st.OldestApp != "3.15.0" {
		t.Fatalf("the Server page shows %q as the oldest app", st.OldestApp)
	}

	invite := alpha.invite("aylin", "Aylin")
	for _, old := range []string{"3.14.16", "3.9.0", "0.1.0", ""} {
		alpha.joinAs(invite, old, http.StatusUpgradeRequired)
	}
	alpha.joinAs(invite, "v3.15.0", 400)
	aylin := alpha.joinAs(invite, "3.15.0", 200)

	code, body := aylin.sessionWith([]string{"3.14.99"}, false)
	if code != http.StatusUpgradeRequired || !strings.Contains(body, "Update Mohur to 3.15.0 or newer") {
		t.Fatalf("an old app signing in: %d %s", code, body)
	}
	// Versions are numbers: 10.0.0 is newer than 3.15.0.
	if code, body := aylin.sessionWith([]string{"10.0.0"}, false); code != 200 {
		t.Fatalf("10.0.0: %d %s", code, body)
	}
	if got := alpha.app("aylin"); got != "10.0.0" {
		t.Fatalf("recorded %q", got)
	}
	if code, _ := aylin.sessionWith([]string{"3.15.0"}, false); code != 200 || alpha.app("aylin") != "3.15.0" {
		t.Fatalf("an app put back to 3.15.0: %d, recorded %q", code, alpha.app("aylin"))
	}
}
