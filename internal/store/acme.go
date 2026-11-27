package store

import (
	"regexp"

	bolt "go.etcd.io/bbolt"
)

// The automatic certificate's state: the Let's Encrypt account key, and each
// certificate with its private key. Each value is sealed with the instance
// key under its own name, like the organization key, so a copy of the
// database alone holds no key that could serve this server's name, and a
// value cannot be moved to another name.

var bucketACME = []byte("acme")

// acmeName matches the names the certificate manager keeps values under,
// such as "acme_account+key" and "mohur.example.com".
var acmeName = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,300}$`)

// maxACMEValue is far above a certificate chain and its key.
const maxACMEValue = 64 << 10

// ACMEGet returns the value kept under name, or ErrNotFound. A value that
// does not open with this instance key is ErrRefused, never used.
func (s *Store) ACMEGet(name string) ([]byte, error) {
	if !acmeName.MatchString(name) {
		return nil, ErrNotFound
	}
	var sealed []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketACME).Get([]byte(name))
		if v == nil {
			return ErrNotFound
		}
		sealed = append([]byte(nil), v...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	plain, err := s.open("acme/"+name, sealed)
	if err != nil {
		return nil, ErrRefused
	}
	return plain, nil
}

// ACMEPut keeps value under name, sealed, replacing what was there.
func (s *Store) ACMEPut(name string, value []byte) error {
	if !acmeName.MatchString(name) || len(value) == 0 || len(value) > maxACMEValue {
		return ErrRefused
	}
	sealed := s.seal("acme/"+name, value)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketACME).Put([]byte(name), sealed)
	})
}

// ACMEDelete removes the value kept under name, if any.
func (s *Store) ACMEDelete(name string) error {
	if !acmeName.MatchString(name) {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketACME).Delete([]byte(name))
	})
}
