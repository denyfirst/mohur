// Package store keeps a Mohur server's state in one bbolt file. Secrets the
// server must use (the organization signing key and admins' authenticator
// seeds) are sealed with an instance key kept in a separate file, so a copy of
// the database alone does not give them away. Message bodies and files are
// end-to-end ciphertext before they arrive and are stored as they are.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	// ErrNotFound means the record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrRefused means the change is not allowed in the record's current state.
	ErrRefused = errors.New("refused")
)

var (
	bucketMeta        = []byte("meta")
	bucketAdmins      = []byte("admins")
	bucketPeople      = []byte("people")
	bucketInvites     = []byte("invites")
	bucketConnections = []byte("connections")
	bucketQueue       = []byte("queue")
	bucketBlobs       = []byte("blobs")
	bucketNonces      = []byte("nonces")
	bucketDirectory   = []byte("directory")
	bucketReports     = []byte("reports")
)

// Store is the server's database.
type Store struct {
	db       *bolt.DB
	aead     cipher.AEAD
	macKey   []byte
	resetKey []byte
	blobDir  string
	clock    atomic.Pointer[func() time.Time]
}

// Open opens or creates the database in dir. keyFile holds the 32-byte
// instance key; it is created with owner-only permissions if missing.
func Open(dir, keyFile string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	blobDir := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return nil, err
	}
	key, err := instanceKey(keyFile)
	if err != nil {
		return nil, err
	}
	sealKey, err := hkdf.Key(sha256.New, key, nil, "mohur/seal/v1", 32)
	if err != nil {
		return nil, err
	}
	macKey, err := hkdf.Key(sha256.New, key, nil, "mohur/recovery/v1", 32)
	if err != nil {
		clear(key)
		return nil, err
	}
	resetKey, err := resetKeyFrom(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sealKey)
	clear(sealKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, "mohur.db"), 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketAdmins, bucketPeople, bucketInvites, bucketConnections, bucketQueue, bucketBlobs, bucketNonces, bucketDirectory, bucketReports, bucketACME} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	st := &Store{db: db, aead: aead, macKey: macKey, resetKey: resetKey, blobDir: blobDir}
	st.SetClock(time.Now)
	return st, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetClock replaces the clock; tests only. It is safe while requests run.
func (s *Store) SetClock(now func() time.Time) { s.clock.Store(&now) }

func (s *Store) now() time.Time { return (*s.clock.Load())() }

func instanceKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the operator chooses the key path at start
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("instance key %s: want 32 bytes, found %d", path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return key, f.Close()
}

// seal encrypts plain for the record named label; the label is bound as
// associated data so a sealed value cannot be moved to another record.
func (s *Store) seal(label string, plain []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic("mohur: random source failed")
	}
	return s.aead.Seal(nonce, nonce, plain, []byte("mohur/seal/v1/"+label))
}

func (s *Store) open(label string, sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, ErrRefused
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], []byte("mohur/seal/v1/"+label))
}

func get[T any](tx *bolt.Tx, bucket []byte, key string) (T, error) {
	var v T
	raw := tx.Bucket(bucket).Get([]byte(key))
	if raw == nil {
		return v, ErrNotFound
	}
	return v, json.Unmarshal(raw, &v)
}

func put(tx *bolt.Tx, bucket []byte, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Bucket(bucket).Put([]byte(key), raw)
}

// Org is this server's organization.
type Org struct {
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Server  string `json:"server"`
	Pub     []byte `json:"pub"`
	Priv    []byte `json:"priv"` // sealed
	Created int64  `json:"created"`
	// DNSChecked is when the TXT record last matched; zero if never.
	DNSChecked int64 `json:"dnsChecked"`
}

// Key returns the organization's public key.
func (o Org) Key() ed25519.PublicKey { return ed25519.PublicKey(o.Pub) }

// Org returns the organization and its private key, or ErrNotFound before setup.
func (s *Store) Org() (Org, ed25519.PrivateKey, error) {
	var o Org
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		o, err = get[Org](tx, bucketMeta, "org")
		return err
	})
	if err != nil {
		return Org{}, nil, err
	}
	seed, err := s.open("org", o.Priv)
	if err != nil || len(seed) != ed25519.SeedSize {
		return Org{}, nil, fmt.Errorf("organization key cannot be unsealed: wrong instance key?")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return o, priv, nil
}

func ed25519GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarkDNS records the time the TXT record last matched, or zero.
func (s *Store) MarkDNS(at int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		o, err := get[Org](tx, bucketMeta, "org")
		if err != nil {
			return err
		}
		o.DNSChecked = at
		return put(tx, bucketMeta, "org", o)
	})
}

// SetupCode is the one-time code printed at first start. Only its hash is kept.
type SetupCode struct {
	Hash    [32]byte `json:"hash"`
	Expires int64    `json:"expires"`
}

// NewSetupCode replaces any setup code with a new one valid for a day.
// It is refused once an admin exists.
func (s *Store) NewSetupCode() (string, error) {
	code := RandomCode(15)
	err := s.db.Update(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bucketAdmins).Cursor().First(); k != nil {
			return ErrRefused
		}
		return put(tx, bucketMeta, "setup", SetupCode{Hash: sha256.Sum256([]byte(code)), Expires: s.now().Add(24 * time.Hour).Unix()})
	})
	return code, err
}

// HasAdmin reports whether setup has finished.
func (s *Store) HasAdmin() bool {
	found := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		k, _ := tx.Bucket(bucketAdmins).Cursor().First()
		found = k != nil
		return nil
	})
	return found
}
