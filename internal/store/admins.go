package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 fixes HMAC-SHA1 for authenticator apps; HMAC does not rely on SHA-1 collision resistance.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/argon2"
)

// Admin is a person who manages this server through its web pages.
type Admin struct {
	Username     string     `json:"username"`
	Salt         []byte     `json:"salt"`
	Sum          []byte     `json:"sum"`
	Seed         []byte     `json:"seed"` // sealed authenticator seed
	LastCounter  int64      `json:"lastCounter"`
	Recovery     [][32]byte `json:"recovery"`
	FactorWindow int64      `json:"factorWindow"`
	FactorCount  int        `json:"factorCount"`
	Created      int64      `json:"created"`
}

// MinPassword is the shortest admin password accepted.
const MinPassword = 15

// PasswordOK reports whether a new password is acceptable.
func PasswordOK(p string) bool {
	return utf8.ValidString(p) && len(p) <= 1024 && utf8.RuneCountInString(p) >= MinPassword
}

// Argon2id: 64 MiB, three passes, four lanes, 128-bit salt, 256-bit output,
// the parameters Keybash uses.
func passwordKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
}

// RandomCode returns n random bytes as unpadded base32 capitals.
func RandomCode(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic("mohur: random source failed")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

// NewSeed returns a fresh authenticator seed.
func NewSeed() string { return RandomCode(20) }

// SeedURI is the authenticator key URI for a seed.
func SeedURI(org, username, seed string) string {
	label := strings.NewReplacer(":", "", "?", "", "&", "", "#", "", "/", "").Replace(org)
	return "otpauth://totp/Mohur%20" + pathEscape(label) + ":" + pathEscape(username) + "?secret=" + seed + "&issuer=Mohur"
}

func pathEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key) // #nosec G401 -- RFC 4226 HMAC-SHA1, as authenticator apps compute it.
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	at := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[at:at+4])&0x7fffffff)%1000000)
}

// TOTP returns the current code for a seed; tests and the lab use it.
func TOTP(seed string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	return hotp(key, uint64(now.Unix()/30)) // #nosec G115 -- time after 1970
}

// totpCounter checks a six-digit code against the previous, current and next
// 30-second step, and returns the greatest matching step after last.
func totpCounter(seed, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if err != nil || len(key) != 20 {
		return 0, false
	}
	defer clear(key)
	cur := now.Unix() / 30
	matched := int64(-1)
	for _, c := range []int64{cur - 1, cur, cur + 1} {
		if c > last && subtle.ConstantTimeCompare([]byte(hotp(key, uint64(c))), []byte(code)) == 1 { // #nosec G115 -- c > last >= -1
			matched = max(matched, c)
		}
	}
	return matched, matched >= 0
}

// CheckSetupCode reports whether code is the current setup code.
func (s *Store) CheckSetupCode(code string) bool {
	ok := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		sc, err := get[SetupCode](tx, bucketMeta, "setup")
		if err != nil {
			return nil
		}
		h := sha256.Sum256([]byte(code))
		ok = sc.Expires > s.now().Unix() && subtle.ConstantTimeCompare(h[:], sc.Hash[:]) == 1
		return nil
	})
	return ok
}

// Setup is everything the first admin enters.
type Setup struct {
	Code, OrgName, Domain, Server, Username, Password, Seed, TOTP string
}

// FinishSetup creates the organization and the first admin in one
// transaction, after checking the setup code and the first authenticator code,
// and spends the setup code. It returns the admin's ten recovery codes.
func (s *Store) FinishSetup(in Setup) ([]string, error) {
	if !PasswordOK(in.Password) {
		return nil, ErrRefused
	}
	now := s.now()
	counter, ok := totpCounter(in.Seed, in.TOTP, now, -1)
	if !ok {
		return nil, ErrRefused
	}
	pub, priv, err := ed25519GenerateKey()
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sum := passwordKey(in.Password, salt)
	codes, hashes := s.newRecovery(in.Username)
	a := Admin{Username: in.Username, Salt: salt, Sum: sum, Seed: s.seal("admin/"+in.Username, []byte(in.Seed)), LastCounter: counter, Recovery: hashes, Created: now.Unix()}
	o := Org{Name: in.OrgName, Domain: in.Domain, Server: in.Server, Pub: pub, Priv: s.seal("org", priv.Seed()), Created: now.Unix()}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bucketAdmins).Cursor().First(); k != nil {
			return ErrRefused
		}
		sc, err := get[SetupCode](tx, bucketMeta, "setup")
		h := sha256.Sum256([]byte(in.Code))
		if err != nil || sc.Expires <= now.Unix() || subtle.ConstantTimeCompare(h[:], sc.Hash[:]) != 1 {
			return ErrRefused
		}
		if err := tx.Bucket(bucketMeta).Delete([]byte("setup")); err != nil {
			return err
		}
		if tx.Bucket(bucketMeta).Get([]byte("org")) == nil {
			if err := put(tx, bucketMeta, "org", o); err != nil {
				return err
			}
		}
		return put(tx, bucketAdmins, a.Username, a)
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// recoveryDigest keys recovery code verifiers with a key derived from the
// instance key, so they cannot be checked offline from the database alone.
func (s *Store) recoveryDigest(owner, code string) [32]byte {
	h := hmac.New(sha256.New, s.macKey)
	_, _ = h.Write([]byte("mohur/recovery/v1/" + owner + "/" + code))
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

func (s *Store) newRecovery(owner string) ([]string, [][32]byte) {
	codes := make([]string, 10)
	hashes := make([][32]byte, 10)
	for i := range codes {
		codes[i] = RandomCode(10)
		hashes[i] = s.recoveryDigest(owner, codes[i])
	}
	return codes, hashes
}

// SignIn checks a username, password and authenticator or recovery code.
// Each admin has five code attempts a minute; failures are recorded too.
func (s *Store) SignIn(username, password, code string) error {
	now := s.now()
	accepted := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		a, err := get[Admin](tx, bucketAdmins, username)
		if err != nil {
			// Spend the same work as a real check so timing does not reveal names.
			_ = passwordKey(password, make([]byte, 16))
			return ErrRefused
		}
		if a.FactorWindow == 0 || now.Unix()-a.FactorWindow >= 60 {
			a.FactorWindow, a.FactorCount = now.Unix(), 0
		}
		if a.FactorCount >= 5 {
			return ErrRefused
		}
		a.FactorCount++
		sum := passwordKey(password, a.Salt)
		if subtle.ConstantTimeCompare(sum, a.Sum) == 1 {
			seed, err := s.open("admin/"+a.Username, a.Seed)
			if err != nil {
				return err
			}
			if c, ok := totpCounter(string(seed), code, now, a.LastCounter); ok {
				a.LastCounter, accepted = c, true
			} else {
				d := s.recoveryDigest(a.Username, strings.ToUpper(strings.ReplaceAll(code, "-", "")))
				for i, h := range a.Recovery {
					if subtle.ConstantTimeCompare(h[:], d[:]) == 1 {
						a.Recovery = append(a.Recovery[:i], a.Recovery[i+1:]...)
						accepted = true
						break
					}
				}
			}
			if accepted {
				a.FactorCount = 0
			}
		}
		// Attempts are committed whether or not they succeed.
		return put(tx, bucketAdmins, a.Username, a)
	})
	if err != nil {
		return err
	}
	if !accepted {
		return ErrRefused
	}
	return nil
}

// RecoveryLeft returns how many recovery codes an admin has left.
func (s *Store) RecoveryLeft(username string) int {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		a, err := get[Admin](tx, bucketAdmins, username)
		if err == nil {
			n = len(a.Recovery)
		}
		return nil
	})
	return n
}
