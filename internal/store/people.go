package store

import (
	"crypto/sha256"
	"strings"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
	bolt "go.etcd.io/bbolt"
)

// Person states.
const (
	Invited = "invited"
	Active  = "active"
)

// InviteLifetime is how long an invite code works.
const InviteLifetime = 72 * time.Hour

// Person is an employee who uses the desktop app.
type Person struct {
	Username      string  `json:"username"`
	Name          string  `json:"name"`
	State         string  `json:"state"`
	Created       int64   `json:"created"`
	InviteExpires int64   `json:"inviteExpires,omitempty"`
	NextDevice    uint32  `json:"nextDevice"`
	Device        *Device `json:"device,omitempty"`
}

// Device is a person's one active device and its public keys.
type Device struct {
	ID             uint32           `json:"id"`
	Label          string           `json:"label"`
	Cert           proto.DeviceCert `json:"cert"`
	RegistrationID uint32           `json:"registrationId"`
	SignedPreKey   proto.PreKey     `json:"signedPreKey"`
	KyberPreKey    proto.PreKey     `json:"kyberPreKey"`
	PreKeys        []proto.PreKey   `json:"preKeys"`
	Joined         int64            `json:"joined"`
	// App is the version the Mohur app on this device gave when it last
	// signed in. It is what the app says about itself.
	App string `json:"app,omitempty"`
}

type invite struct {
	Username string `json:"username"`
	Expires  int64  `json:"expires"`
}

// MaxPreKeys bounds the one-time prekeys a device may keep on the server.
const MaxPreKeys = 200

func inviteKey(code string) string {
	h := sha256.Sum256([]byte(NormalizeCode(code)))
	return proto.B64(h[:])
}

// NormalizeCode removes the dashes and spaces people paste with a code.
func NormalizeCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
}

// Invite creates a person, or renews the invite of one not yet active, and
// returns a new one-time code. Any earlier code for the person stops working.
func (s *Store) Invite(username, name string) (string, Person, error) {
	code := RandomCode(15)
	now := s.now()
	var p Person
	err := s.db.Update(func(tx *bolt.Tx) error {
		existing, err := get[Person](tx, bucketPeople, username)
		switch {
		case err == ErrNotFound:
			p = Person{Username: username, Name: name, State: Invited, Created: now.Unix(), NextDevice: 1}
		case err != nil:
			return err
		case existing.State == Active:
			return ErrRefused
		default:
			p = existing
			p.Name = name
		}
		if err := dropInvites(tx, username); err != nil {
			return err
		}
		p.InviteExpires = now.Add(InviteLifetime).Unix()
		if err := put(tx, bucketInvites, inviteKey(code), invite{Username: username, Expires: p.InviteExpires}); err != nil {
			return err
		}
		return put(tx, bucketPeople, username, p)
	})
	return code, p, err
}

func dropInvites(tx *bolt.Tx, username string) error {
	b := tx.Bucket(bucketInvites)
	var drop [][]byte
	err := b.ForEach(func(k, v []byte) error {
		var in invite
		if jsonUnmarshal(v, &in) == nil && in.Username == username {
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
}

// Join is what a new device sends with its invite code.
type Join struct {
	Code           string
	Label          string
	IdentityKey    string
	AuthKey        string
	RegistrationID uint32
	SignedPreKey   proto.PreKey
	KyberPreKey    proto.PreKey
	PreKeys        []proto.PreKey
}

// Redeem spends an invite code, makes the person active and signs the device
// certificate. The code works once; a second redeem of the same code fails.
func (s *Store) Redeem(j Join, sign func(*proto.DeviceCert)) (Person, error) {
	now := s.now()
	o, _, err := s.Org()
	if err != nil {
		return Person{}, err
	}
	var p Person
	err = s.db.Update(func(tx *bolt.Tx) error {
		k := inviteKey(j.Code)
		in, err := get[invite](tx, bucketInvites, k)
		if err != nil || in.Expires <= now.Unix() {
			return ErrRefused
		}
		p, err = get[Person](tx, bucketPeople, in.Username)
		if err != nil || p.State != Invited {
			return ErrRefused
		}
		if err := tx.Bucket(bucketInvites).Delete([]byte(k)); err != nil {
			return err
		}
		d := &Device{ID: p.NextDevice, Label: j.Label, RegistrationID: j.RegistrationID, SignedPreKey: j.SignedPreKey, KyberPreKey: j.KyberPreKey, PreKeys: j.PreKeys, Joined: now.Unix()}
		d.Cert = proto.DeviceCert{Address: p.Username + "@" + o.Domain, Name: p.Name, Device: d.ID, IdentityKey: j.IdentityKey, AuthKey: j.AuthKey, Issued: now.Unix()}
		sign(&d.Cert)
		p.NextDevice++
		p.Device, p.State, p.InviteExpires = d, Active, 0
		return put(tx, bucketPeople, p.Username, p)
	})
	return p, err
}

// Person returns one person.
func (s *Store) Person(username string) (Person, error) {
	var p Person
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		p, err = get[Person](tx, bucketPeople, username)
		return err
	})
	return p, err
}

// People returns everyone, in username order.
func (s *Store) People() ([]Person, error) {
	var out []Person
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPeople).ForEach(func(_, v []byte) error {
			var p Person
			if err := jsonUnmarshal(v, &p); err != nil {
				return err
			}
			out = append(out, p)
			return nil
		})
	})
	return out, err
}

// Remove deletes a person, their device, invites, queued messages and their
// place on partners' chosen lists.
func (s *Store) Remove(username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketPeople).Get([]byte(username)) == nil {
			return ErrNotFound
		}
		if err := dropInvites(tx, username); err != nil {
			return err
		}
		if q := tx.Bucket(bucketQueue); q.Bucket([]byte(username)) != nil {
			if err := q.DeleteBucket([]byte(username)); err != nil {
				return err
			}
		}
		if err := forgetAccess(tx, username); err != nil {
			return err
		}
		return tx.Bucket(bucketPeople).Delete([]byte(username))
	})
}

// ResetDevice removes a person's device so they can be invited again, for a
// lost or replaced computer. Partners will see a new device when they rejoin.
func (s *Store) ResetDevice(username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		p, err := get[Person](tx, bucketPeople, username)
		if err != nil {
			return err
		}
		if p.State != Active {
			return ErrRefused
		}
		p.Device, p.State = nil, Invited
		if q := tx.Bucket(bucketQueue); q.Bucket([]byte(username)) != nil {
			if err := q.DeleteBucket([]byte(username)); err != nil {
				return err
			}
		}
		return put(tx, bucketPeople, username, p)
	})
}

// SetDeviceApp records the app version a person's current device gave, and
// writes only when it changed.
func (s *Store) SetDeviceApp(username string, device uint32, app string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		p, err := get[Person](tx, bucketPeople, username)
		if err != nil || p.State != Active || p.Device == nil || p.Device.ID != device {
			return ErrRefused
		}
		if p.Device.App == app {
			return nil
		}
		p.Device.App = app
		return put(tx, bucketPeople, username, p)
	})
}

// TakeBundle returns the person's device bundle and spends one one-time
// prekey, if any are left.
func (s *Store) TakeBundle(username string) ([]proto.Bundle, error) {
	var out []proto.Bundle
	err := s.db.Update(func(tx *bolt.Tx) error {
		p, err := get[Person](tx, bucketPeople, username)
		if err != nil || p.State != Active || p.Device == nil {
			return ErrNotFound
		}
		d := p.Device
		b := proto.Bundle{Cert: d.Cert, RegistrationID: d.RegistrationID, SignedPreKey: d.SignedPreKey, KyberPreKey: d.KyberPreKey}
		if len(d.PreKeys) > 0 {
			pk := d.PreKeys[0]
			b.PreKey = &pk
			d.PreKeys = d.PreKeys[1:]
		}
		out = append(out, b)
		return put(tx, bucketPeople, username, p)
	})
	return out, err
}

// AddPreKeys stores more one-time prekeys and, optionally, new signed ones.
func (s *Store) AddPreKeys(username string, device uint32, keys []proto.PreKey, signed, kyber *proto.PreKey) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		p, err := get[Person](tx, bucketPeople, username)
		if err != nil || p.Device == nil || p.Device.ID != device {
			return ErrRefused
		}
		d := p.Device
		seen := map[uint32]bool{}
		for _, k := range d.PreKeys {
			seen[k.ID] = true
		}
		for _, k := range keys {
			if !seen[k.ID] && len(d.PreKeys) < MaxPreKeys {
				d.PreKeys = append(d.PreKeys, k)
				seen[k.ID] = true
			}
		}
		if signed != nil {
			d.SignedPreKey = *signed
		}
		if kyber != nil {
			d.KyberPreKey = *kyber
		}
		n = len(d.PreKeys)
		return put(tx, bucketPeople, username, p)
	})
	return n, err
}
