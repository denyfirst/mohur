package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/denyfirst/mohur/internal/proto"
	bolt "go.etcd.io/bbolt"
)

// MaxQueued bounds the envelopes waiting for one person.
const MaxQueued = 5000

type queued struct {
	Env     proto.Envelope `json:"env"`
	Expires int64          `json:"expires"`
}

// Enqueue stores an envelope for a local recipient until their app fetches it.
func (s *Store) Enqueue(e proto.Envelope) error {
	user, _, err := proto.Address(e.To)
	if err != nil {
		return ErrRefused
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		p, err := get[Person](tx, bucketPeople, user)
		if err != nil || p.Device == nil || p.Device.ID != e.ToDevice {
			return ErrNotFound
		}
		b, err := tx.Bucket(bucketQueue).CreateBucketIfNotExists([]byte(user))
		if err != nil {
			return err
		}
		if b.Stats().KeyN >= MaxQueued {
			return ErrRefused
		}
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		var k [8]byte
		binary.BigEndian.PutUint64(k[:], seq)
		raw, err := json.Marshal(queued{Env: e, Expires: s.now().Add(proto.QueueLifetime).Unix()})
		if err != nil {
			return err
		}
		return b.Put(k[:], raw)
	})
}

// Inbox returns up to limit waiting envelopes for a person's device, oldest first.
func (s *Store) Inbox(user string, device uint32, limit int) ([]proto.Envelope, error) {
	var out []proto.Envelope
	now := s.now().Unix()
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQueue).Bucket([]byte(user))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil && len(out) < limit; k, v = c.Next() {
			var q queued
			if err := json.Unmarshal(v, &q); err != nil {
				return err
			}
			if q.Expires > now && q.Env.ToDevice == device {
				out = append(out, q.Env)
			}
		}
		return nil
	})
	return out, err
}

// Ack deletes delivered envelopes by id.
func (s *Store) Ack(user string, ids []string) error {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQueue).Bucket([]byte(user))
		if b == nil {
			return nil
		}
		var drop [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var q queued
			if json.Unmarshal(v, &q) == nil && want[q.Env.ID] {
				drop = append(drop, append([]byte(nil), k...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range drop {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// Blob is an encrypted file waiting for its recipient.
type Blob struct {
	ID      string `json:"id"`
	To      string `json:"to"`
	From    string `json:"from"`
	Size    int64  `json:"size"`
	Created int64  `json:"created"`
}

// PutBlob stores up to proto.MaxBlob bytes from r as a blob for a recipient.
func (s *Store) PutBlob(id, from, to string, r io.Reader) (Blob, error) {
	if !proto.ID(id) {
		return Blob{}, ErrRefused
	}
	path := filepath.Join(s.blobDir, id)
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- id is validated base64url
	if err != nil {
		return Blob{}, ErrRefused
	}
	n, err := io.Copy(f, io.LimitReader(r, proto.MaxBlob+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || n == 0 || n > proto.MaxBlob {
		_ = os.Remove(tmp)
		return Blob{}, ErrRefused
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return Blob{}, err
	}
	b := Blob{ID: id, To: to, From: from, Size: n, Created: s.now().Unix()}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketBlobs).Get([]byte(id)) != nil {
			return ErrRefused
		}
		return put(tx, bucketBlobs, id, b)
	})
	if err != nil {
		_ = os.Remove(path)
	}
	return b, err
}

// Blob returns a blob's record.
func (s *Store) Blob(id string) (Blob, error) {
	var b Blob
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		b, err = get[Blob](tx, bucketBlobs, id)
		return err
	})
	return b, err
}

// OpenBlob opens a blob's bytes.
func (s *Store) OpenBlob(id string) (*os.File, error) {
	if !proto.ID(id) {
		return nil, ErrRefused
	}
	return os.Open(filepath.Join(s.blobDir, id)) // #nosec G304 -- id is validated base64url
}

// DeleteBlob removes a blob.
func (s *Store) DeleteBlob(id string) error {
	if !proto.ID(id) {
		return ErrRefused
	}
	err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketBlobs).Delete([]byte(id)) })
	if rerr := os.Remove(filepath.Join(s.blobDir, id)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) && err == nil {
		err = rerr
	}
	return err
}

// FreshNonce records a federation request nonce and reports whether it was new.
func (s *Store) FreshNonce(nonce string) bool {
	fresh := false
	_ = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketNonces)
		if b.Get([]byte(nonce)) != nil {
			return nil
		}
		var exp [8]byte
		binary.BigEndian.PutUint64(exp[:], uint64(s.now().Add(2*proto.FedClockSkew).Unix())) // #nosec G115 -- time after 1970
		fresh = true
		return b.Put([]byte(nonce), exp[:])
	})
	return fresh
}

// Sweep deletes expired envelopes, blobs and nonces.
func (s *Store) Sweep() error {
	now := s.now().Unix()
	var oldBlobs []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		n := tx.Bucket(bucketNonces)
		var drop [][]byte
		_ = n.ForEach(func(k, v []byte) error {
			if len(v) != 8 || int64(binary.BigEndian.Uint64(v)) < now { // #nosec G115 -- stored from Unix time
				drop = append(drop, append([]byte(nil), k...))
			}
			return nil
		})
		for _, k := range drop {
			if err := n.Delete(k); err != nil {
				return err
			}
		}
		q := tx.Bucket(bucketQueue)
		err := q.ForEachBucket(func(user []byte) error {
			b := q.Bucket(user)
			var old [][]byte
			_ = b.ForEach(func(k, v []byte) error {
				var x queued
				if json.Unmarshal(v, &x) != nil || x.Expires <= now {
					old = append(old, append([]byte(nil), k...))
				}
				return nil
			})
			for _, k := range old {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		return tx.Bucket(bucketBlobs).ForEach(func(k, v []byte) error {
			var b Blob
			if json.Unmarshal(v, &b) != nil || b.Created+int64(proto.QueueLifetime.Seconds()) <= now {
				oldBlobs = append(oldBlobs, string(k))
			}
			return nil
		})
	})
	for _, id := range oldBlobs {
		_ = s.DeleteBlob(id)
	}
	return err
}
