package store

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// A reset code lets whoever runs the server set a new password and
// authenticator for an admin who can no longer sign in. `mohurd reset-admin`
// makes it from the instance key alone, so the server keeps running: the code
// is a random part and a MAC over it and the minute it was made, keyed from the
// instance key. The server accepts a code for up to an hour, once. Anyone who
// can read the instance key can already open every sealed secret, so the code
// gives the server's operator nothing new.

// ResetLifetime is how long a reset code works.
const ResetLifetime = time.Hour

const (
	resetRandom = 6 // bytes
	resetMAC    = 9 // bytes; 72 bits against guessing, which is also rate limited
)

func resetKeyFrom(instanceKey []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, instanceKey, nil, "mohur/reset/v1", 32)
}

func resetTag(key []byte, minute int64, random []byte) []byte {
	var m [8]byte
	binary.BigEndian.PutUint64(m[:], uint64(minute)) // #nosec G115 -- minutes after 1970
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("mohur/reset/v1"))
	_, _ = h.Write(m[:])
	_, _ = h.Write(random)
	return h.Sum(nil)[:resetMAC]
}

// ResetCode makes a reset code from the instance key in keyFile. Unlike Open,
// it never creates the key: a missing key means the wrong file.
func ResetCode(keyFile string, now time.Time) (string, error) {
	key, err := os.ReadFile(keyFile) // #nosec G304 -- the operator names the key file
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		clear(key)
		return "", fmt.Errorf("instance key %s: want 32 bytes, found %d", keyFile, len(key))
	}
	rk, err := resetKeyFrom(key)
	clear(key)
	if err != nil {
		return "", err
	}
	random := make([]byte, resetRandom)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	code := append(random, resetTag(rk, now.Unix()/60, random)...)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(code), nil
}

// resetRandomPart returns the random part of a code that is genuine and still
// within its hour, or false.
func (s *Store) resetRandomPart(code string, now time.Time) ([]byte, bool) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	code = NormalizeCode(code)
	if len(code) != enc.EncodedLen(resetRandom+resetMAC) {
		return nil, false
	}
	raw, err := enc.DecodeString(code)
	if err != nil || len(raw) != resetRandom+resetMAC {
		return nil, false
	}
	random, tag := raw[:resetRandom], raw[resetRandom:]
	cur := now.Unix() / 60
	window := int64(ResetLifetime / time.Minute)
	for m := cur - window + 1; m <= cur; m++ {
		if hmac.Equal(resetTag(s.resetKey, m, random), tag) {
			return random, true
		}
	}
	return nil, false
}

// resetSpent holds the random parts of used codes until they would have
// expired anyway.
type resetSpent map[string]int64

func spentCodes(tx *bolt.Tx) (resetSpent, error) {
	sp, err := get[resetSpent](tx, bucketMeta, "reset-spent")
	if errors.Is(err, ErrNotFound) {
		return resetSpent{}, nil
	}
	return sp, err
}

// CheckResetCode reports whether code is a genuine, unexpired, unused reset
// code and an admin exists to reset.
func (s *Store) CheckResetCode(code string) bool {
	random, ok := s.resetRandomPart(code, s.now())
	if !ok {
		return false
	}
	usable := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		sp, err := spentCodes(tx)
		if err != nil {
			return nil
		}
		k, _ := tx.Bucket(bucketAdmins).Cursor().First()
		_, used := sp[hex.EncodeToString(random)]
		usable = k != nil && !used
		return nil
	})
	return usable
}

// AdminName returns the admin's name, or "" before setup. Setup creates the
// only admin; a reset is for that admin.
func (s *Store) AdminName() string {
	name := ""
	_ = s.db.View(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bucketAdmins).Cursor().First(); k != nil {
			name = string(k)
		}
		return nil
	})
	return name
}

// Reset is what the admin enters after a reset code.
type Reset struct {
	Code, Username, Password, Seed, TOTP string
}

// ResetAdmin gives an admin a new password, authenticator and recovery codes,
// spends the reset code and returns the new recovery codes. It returns
// ErrNotFound when the code or the admin is not usable and ErrRefused when the
// password or the authenticator code is not accepted; then the code still
// works.
func (s *Store) ResetAdmin(in Reset) ([]string, error) {
	now := s.now()
	random, ok := s.resetRandomPart(in.Code, now)
	if !ok {
		return nil, ErrNotFound
	}
	if !PasswordOK(in.Password) {
		return nil, ErrRefused
	}
	counter, ok := totpCounter(in.Seed, in.TOTP, now, -1)
	if !ok {
		return nil, ErrRefused
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sum := passwordKey(in.Password, salt)
	codes, hashes := s.newRecovery(in.Username)
	err := s.db.Update(func(tx *bolt.Tx) error {
		sp, err := spentCodes(tx)
		if err != nil {
			return err
		}
		id := hex.EncodeToString(random)
		if _, used := sp[id]; used {
			return ErrNotFound
		}
		a, err := get[Admin](tx, bucketAdmins, in.Username)
		if err != nil {
			return ErrNotFound
		}
		a.Salt, a.Sum = salt, sum
		a.Seed = s.seal("admin/"+a.Username, []byte(in.Seed))
		a.LastCounter, a.Recovery = counter, hashes
		a.FactorWindow, a.FactorCount = 0, 0
		for k, until := range sp {
			if until <= now.Unix() {
				delete(sp, k)
			}
		}
		sp[id] = now.Add(ResetLifetime + time.Minute).Unix()
		if err := put(tx, bucketMeta, "reset-spent", sp); err != nil {
			return err
		}
		return put(tx, bucketAdmins, a.Username, a)
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}
