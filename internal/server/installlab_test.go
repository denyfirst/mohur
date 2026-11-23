//go:build installlab

package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
)

// TestInstalledServer drives a mohurd that scripts/install.sh installed under
// systemd, with all its sandboxing, through setup, sign-in, an invite, a join
// and an app session. scripts/install-lab.sh runs it with:
// MOHUR_LAB_URL (https://name:port), MOHUR_LAB_CA (PEM) and MOHUR_LAB_CODE.
func TestInstalledServer(t *testing.T) {
	base, caFile, code := os.Getenv("MOHUR_LAB_URL"), os.Getenv("MOHUR_LAB_CA"), os.Getenv("MOHUR_LAB_CODE")
	if base == "" || caFile == "" || code == "" {
		t.Skip("run by scripts/install-lab.sh")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no CA certificate")
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	call := func(method, path string, in any, want int, out any) {
		t.Helper()
		var body io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			body = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, base+path, body)
		req.Header.Set("X-Mohur", "1")
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d, want %d: %s", method, path, resp.StatusCode, want, b)
		}
		if out != nil {
			if err := json.Unmarshal(b, out); err != nil {
				t.Fatal(err)
			}
		}
	}

	var start struct {
		Seed string `json:"seed"`
	}
	call("POST", "/admin/api/setup/start", map[string]any{"code": code}, 200, &start)
	call("POST", "/admin/api/setup/finish", map[string]any{"code": code, "orgName": "CI LLC", "domain": "ci.test", "server": "mohur.ci.test:8443",
		"username": "admin", "password": "install lab password", "totp": store.TOTP(start.Seed, time.Now())}, 200, nil)
	call("POST", "/admin/api/setup/start", map[string]any{"code": code}, 403, nil)

	var doc proto.OrgDoc
	call("GET", "/.well-known/mohur", nil, 200, &doc)
	if _, err := doc.Check(); err != nil || doc.Domain != "ci.test" {
		t.Fatalf("organization document: %+v, %v", doc, err)
	}
	var inv struct {
		Invite string `json:"invite"`
	}
	call("POST", "/admin/api/people/invite", map[string]any{"username": "aylin", "name": "Aylin"}, 200, &inv)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var joined struct {
		Cert proto.DeviceCert `json:"cert"`
	}
	call("POST", "/api/v1/join", map[string]any{"invite": inv.Invite, "label": "CI", "identityKey": randomB64(33, 5), "authKey": proto.B64(pub), "registrationId": 7,
		"signedPreKey": map[string]any{"id": 1, "pub": randomB64(33, 5), "sig": randomB64(64, 0)},
		"kyberPreKey":  map[string]any{"id": 1, "pub": randomB64(1569, 8), "sig": randomB64(64, 0)}}, 200, &joined)
	var ch struct {
		Nonce string `json:"nonce"`
	}
	call("POST", "/api/v1/session/challenge", map[string]any{"address": joined.Cert.Address, "device": joined.Cert.Device}, 200, &ch)
	sig := proto.Sign(priv, proto.ContextSession, "ci.test", joined.Cert.Address, strconv.Itoa(int(joined.Cert.Device)), ch.Nonce)
	call("POST", "/api/v1/session", map[string]any{"address": joined.Cert.Address, "device": joined.Cert.Device, "nonce": ch.Nonce, "sig": sig}, 200, nil)
}
