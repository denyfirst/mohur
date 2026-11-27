package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/denyfirst/mohur/internal/store"
)

// certFiles writes a self-signed certificate for name and its key.
func certFiles(t *testing.T, name string) (cert, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, key = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestTheCertificateComesFromExactlyOnePlace(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, filepath.Join(dir, "instance.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	log := slog.New(slog.DiscardHandler)
	cert, key := certFiles(t, "mohur.example.test")

	// Automatic: Let's Encrypt's check is answered, and renewal runs.
	c, renew, err := serverTLS("mohur.example.test", "", "", st, log)
	if err != nil || renew == nil || !slices.Contains(c.NextProtos, acme.ALPNProto) || c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("automatic: %v, renew %v", err, renew != nil)
	}

	// Files: the certificate is read at once, and nothing else runs.
	c, renew, err = serverTLS("", cert, key, st, log)
	if err != nil || renew != nil || c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("files: %v", err)
	}
	got, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "mohur.example.test"})
	if err != nil || got == nil {
		t.Fatalf("files serve no certificate: %v", err)
	}

	for _, bad := range []struct{ auto, cert, key, want string }{
		{"", "", "", "give -auto-cert NAME, or -cert and -cert-key"},
		{"", cert, "", "give -auto-cert NAME, or -cert and -cert-key"},
		{"", "", key, "give -auto-cert NAME, or -cert and -cert-key"},
		{"mohur.example.test", cert, key, "not both"},
		{"mohur.example.test", cert, "", "not both"},
		{"mohur.example.test", "", key, "not both"},
		{"Mohur.Example.Test", "", "", "-auto-cert: give the server's name"},
		{"mohur.example.test:443", "", "", "-auto-cert: give the server's name"},
		{"192.0.2.1", "", "", "-auto-cert: give the server's name"},
		{"", cert, filepath.Join(dir, "missing.pem"), "TLS certificate"},
		{"", key, key, "TLS certificate"},
	} {
		_, _, err := serverTLS(bad.auto, bad.cert, bad.key, st, log)
		if err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%q %q %q: %v, want %q", bad.auto, bad.cert, bad.key, err, bad.want)
		}
	}
}
