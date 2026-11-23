package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestDomainNormalizesAndRefuses(t *testing.T) {
	good := map[string]string{"Example.COM": "example.com", " partner.az ": "partner.az", "bücher.de": "xn--bcher-kva.de", "a.b.c.example.com": "a.b.c.example.com"}
	for in, want := range good {
		if got, err := Domain(in); err != nil || got != want {
			t.Errorf("Domain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost", "example.com.", "127.0.0.1", "exa mple.com", "user@example.com", "example.com:443", "https://example.com", "-x.com", "x-.com", strings.Repeat("a", 64) + ".com"} {
		if got, err := Domain(bad); err == nil {
			t.Errorf("Domain(%q) = %q, want refusal", bad, got)
		}
	}
}

func TestServerMustBeUnderTheDomain(t *testing.T) {
	for _, s := range []string{"example.com", "mohur.example.com", "a.b.example.com:8443"} {
		if _, err := ServerName(s, "example.com"); err != nil {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{"evil.com", "example.com.evil.com", "notexample.com", "mohur.example.com:0", "mohur.example.com:99999", "mohur.example.com:080", "Mohur.example.com"} {
		if _, err := ServerName(s, "example.com"); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestParseTXT(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	rec := TXTValue("mohur.example.com", pub)
	got, err := ParseTXT([]string{"google-site-verification=x", rec}, "example.com")
	if err != nil || got.Server != "mohur.example.com" || !got.Key.Equal(pub) {
		t.Fatalf("ParseTXT = %+v, %v", got, err)
	}
	bad := [][]string{
		nil,
		{rec, rec},
		{"v=mohur1 server=mohur.example.com"},
		{"v=mohur1 key=" + B64(pub)},
		{"v=mohur1 server=mohur.other.com key=" + B64(pub)},
		{"v=mohur1 server=mohur.example.com key=" + B64(pub) + " key=" + B64(pub)},
		{"v=mohur1 server=mohur.example.com key=" + B64(pub[:31])},
		{"v=mohur1 server=mohur.example.com key=" + B64(pub) + "="},
	}
	for _, records := range bad {
		if _, err := ParseTXT(records, "example.com"); err == nil {
			t.Errorf("ParseTXT(%q) accepted", records)
		}
	}
}

func TestDeviceCertificateCheck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	auth, _, _ := ed25519.GenerateKey(rand.Reader)
	ik := make([]byte, 33)
	_, _ = rand.Read(ik)
	ik[0] = 5
	c := DeviceCert{Address: "aylin@example.com", Name: "Aylin", Device: 1, IdentityKey: B64(ik), AuthKey: B64(auth), Issued: 1700000000}
	SignDevice(&c, priv)
	if err := c.Check(pub, "example.com"); err != nil {
		t.Fatalf("genuine certificate: %v", err)
	}
	if c.Check(other, "example.com") == nil {
		t.Error("certificate accepted under another organization's key")
	}
	if c.Check(pub, "other.com") == nil {
		t.Error("certificate accepted for another domain")
	}
	// The other organization signs a certificate for an address in ours.
	stolen := c
	SignDevice(&stolen, otherPriv)
	if stolen.Check(other, "other.com") == nil {
		t.Error("certificate for an address outside the signer's domain accepted")
	}
	for name, change := range map[string]func(*DeviceCert){
		"address":  func(d *DeviceCert) { d.Address = "nigar@example.com" },
		"name":     func(d *DeviceCert) { d.Name = "Nigar" },
		"device":   func(d *DeviceCert) { d.Device = 2 },
		"identity": func(d *DeviceCert) { d.IdentityKey = B64(append([]byte{5}, make([]byte, 32)...)) },
		"auth":     func(d *DeviceCert) { d.AuthKey = B64(other) },
		"issued":   func(d *DeviceCert) { d.Issued++ },
	} {
		d := c
		change(&d)
		if d.Check(pub, "example.com") == nil {
			t.Errorf("changed %s still verifies", name)
		}
	}
}

func TestSignedBytesAreUnambiguous(t *testing.T) {
	a := SignedBytes("ctx", "ab", "c")
	b := SignedBytes("ctx", "a", "bc")
	if string(a) == string(b) {
		t.Fatal("different fields gave the same bytes")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := Sign(priv, ContextOrg, "x")
	if Verify(priv.Public().(ed25519.PublicKey), sig, ContextDevice, "x") {
		t.Fatal("a signature verified under another context")
	}
}

func TestFingerprintIsTheSameOnBothSides(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	if Fingerprint(a, b) != Fingerprint(b, a) || len(strings.Fields(Fingerprint(a, b))) != 12 {
		t.Fatalf("fingerprint %q / %q", Fingerprint(a, b), Fingerprint(b, a))
	}
}
