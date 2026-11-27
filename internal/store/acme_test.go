package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestTheCertificateStateIsSealedAndBoundToItsName(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "instance.key")
	s, err := Open(dir, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert := []byte("-----BEGIN EC PRIVATE KEY-----\nsecret-key-material\n-----END EC PRIVATE KEY-----\n")
	account := []byte("-----BEGIN EC PRIVATE KEY-----\naccount-key-material\n-----END EC PRIVATE KEY-----\n")
	if err := s.ACMEPut("mohur.example.com", cert); err != nil {
		t.Fatal(err)
	}
	if err := s.ACMEPut("acme_account+key", account); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ACMEGet("mohur.example.com"); err != nil || !bytes.Equal(got, cert) {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := s.ACMEGet("other.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a name never kept: %v", err)
	}

	// A renewal replaces the value.
	renewed := []byte("renewed-certificate")
	if err := s.ACMEPut("mohur.example.com", renewed); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ACMEGet("mohur.example.com"); !bytes.Equal(got, renewed) {
		t.Fatal("the renewal did not replace the value")
	}
	if err := s.ACMEPut("mohur.example.com", cert); err != nil {
		t.Fatal(err)
	}

	// Moved to another name, a sealed value does not open.
	_ = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketACME)
		return b.Put([]byte("other.example.com"), append([]byte(nil), b.Get([]byte("acme_account+key"))...))
	})
	if _, err := s.ACMEGet("other.example.com"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the account key opened under a certificate's name: %v", err)
	}

	// A changed byte is refused, not used.
	_ = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketACME)
		v := append([]byte(nil), b.Get([]byte("acme_account+key"))...)
		v[len(v)-1] ^= 1
		return b.Put([]byte("acme_account+key"), v)
	})
	if _, err := s.ACMEGet("acme_account+key"); !errors.Is(err, ErrRefused) {
		t.Fatalf("an altered value opened: %v", err)
	}

	if err := s.ACMEDelete("mohur.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ACMEGet("mohur.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := s.ACMEPut("mohur.example.com", cert); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	// The database file holds no key material in the clear.
	raw, err := os.ReadFile(filepath.Join(dir, "mohur.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-key-material", "account-key-material", "PRIVATE KEY"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("the database holds %q in the clear", secret)
		}
	}

	// It survives a restart with the same instance key, and opens with no other.
	if s, err = Open(dir, keyFile); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ACMEGet("mohur.example.com"); err != nil || !bytes.Equal(got, cert) {
		t.Fatalf("after a restart: %q, %v", got, err)
	}
	_ = s.Close()
	other := filepath.Join(t.TempDir(), "other.key")
	if s, err = Open(dir, other); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.ACMEGet("mohur.example.com"); !errors.Is(err, ErrRefused) {
		t.Fatalf("opened with another instance key: %v", err)
	}
}

func TestTheCertificateStateRefusesOddNamesAndSizes(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, filepath.Join(dir, "instance.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for _, name := range []string{"", "a/b", "../x", "a b", "a\x00b", "é.example", strings.Repeat("a", 301)} {
		if err := s.ACMEPut(name, []byte("x")); !errors.Is(err, ErrRefused) {
			t.Errorf("put %q: %v", name, err)
		}
		if _, err := s.ACMEGet(name); !errors.Is(err, ErrNotFound) {
			t.Errorf("get %q: %v", name, err)
		}
	}
	if err := s.ACMEPut("mohur.example.com", nil); !errors.Is(err, ErrRefused) {
		t.Errorf("an empty value: %v", err)
	}
	if err := s.ACMEPut("mohur.example.com", make([]byte, maxACMEValue+1)); !errors.Is(err, ErrRefused) {
		t.Errorf("an oversized value: %v", err)
	}
	if err := s.ACMEPut("mohur.example.com", make([]byte, maxACMEValue)); err != nil {
		t.Errorf("the largest value: %v", err)
	}
}
