package store

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
	bolt "go.etcd.io/bbolt"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// Connection states.
const (
	Outgoing   = "outgoing"    // we asked; waiting for them
	Incoming   = "incoming"    // they asked; waiting for our admin
	Connected  = "connected"   // both accepted
	KeyChanged = "key-changed" // their key no longer matches; paused until our admin accepts it
)

// Connection is a partner organization.
type Connection struct {
	Domain  string `json:"domain"`
	Name    string `json:"name"`
	Server  string `json:"server"`
	Key     string `json:"key"`
	State   string `json:"state"`
	Created int64  `json:"created"`
	Updated int64  `json:"updated"`
	// NewKey, NewName and NewServer hold what the partner shows now when its
	// key no longer matches the pinned one.
	NewKey    string `json:"newKey,omitempty"`
	NewName   string `json:"newName,omitempty"`
	NewServer string `json:"newServer,omitempty"`
	Checked   int64  `json:"checked"`
	// Chosen limits who here may write with this partner to the usernames in
	// People. Without it, everyone here may. Each side decides only for its
	// own people; the partner never sees this list, only its result.
	Chosen bool     `json:"chosen,omitempty"`
	People []string `json:"people,omitempty"`
}

// Allows reports whether the person here with this username may write with
// this partner and be written to by its people.
func (c Connection) Allows(username string) bool {
	return !c.Chosen || slices.Contains(c.People, username)
}

// MaxChosen bounds the people chosen for one partner.
const MaxChosen = 10000

// SetAccess sets who here may write with a partner: everyone, or only the
// chosen people, who must be people of this organization.
func (s *Store) SetAccess(domain string, chosen bool, people []string) (Connection, error) {
	var c Connection
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		if c, err = get[Connection](tx, bucketConnections, domain); err != nil {
			return err
		}
		var list []string
		if chosen {
			if len(people) > MaxChosen {
				return ErrRefused
			}
			list = []string{}
			for _, u := range people {
				if tx.Bucket(bucketPeople).Get([]byte(u)) == nil {
					return ErrRefused
				}
				if !slices.Contains(list, u) {
					list = append(list, u)
				}
			}
			slices.Sort(list)
		}
		c.Chosen, c.People, c.Updated = chosen, list, s.now().Unix()
		return put(tx, bucketConnections, domain, c)
	})
	return c, err
}

// forgetAccess takes a removed person off every partner's chosen list, so a
// new person who later gets the same username does not inherit it.
func forgetAccess(tx *bolt.Tx, username string) error {
	b := tx.Bucket(bucketConnections)
	var changed []Connection
	err := b.ForEach(func(_, v []byte) error {
		var c Connection
		if err := json.Unmarshal(v, &c); err != nil {
			return err
		}
		if i := slices.Index(c.People, username); i >= 0 {
			c.People = slices.Delete(c.People, i, i+1)
			changed = append(changed, c)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, c := range changed {
		if err := put(tx, bucketConnections, c.Domain, c); err != nil {
			return err
		}
	}
	return nil
}

// MaxIncoming bounds unanswered incoming requests, so a stranger cannot fill
// the admin's list.
const MaxIncoming = 50

// Connection returns one partner.
func (s *Store) Connection(domain string) (Connection, error) {
	var c Connection
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		c, err = get[Connection](tx, bucketConnections, domain)
		return err
	})
	return c, err
}

// Connections returns all partners.
func (s *Store) Connections() ([]Connection, error) {
	var out []Connection
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConnections).ForEach(func(_, v []byte) error {
			var c Connection
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			out = append(out, c)
			return nil
		})
	})
	return out, err
}

// Ask records that our admin asked to connect to a verified organization. If
// that organization had already asked us with the same key, both sides have
// now agreed and the connection is made.
func (s *Store) Ask(o proto.OrgDoc) (Connection, error) {
	now := s.now().Unix()
	var c Connection
	err := s.db.Update(func(tx *bolt.Tx) error {
		existing, err := get[Connection](tx, bucketConnections, o.Domain)
		switch {
		case err == ErrNotFound:
			c = Connection{Domain: o.Domain, Name: o.Name, Server: o.Server, Key: o.Key, State: Outgoing, Created: now}
		case err != nil:
			return err
		case existing.State == Incoming && existing.Key == o.Key:
			c = existing
			c.State = Connected
		case existing.State == Outgoing:
			c = existing
			c.Name, c.Server, c.Key = o.Name, o.Server, o.Key
		default:
			return ErrRefused
		}
		c.Updated, c.Checked = now, now
		return put(tx, bucketConnections, c.Domain, c)
	})
	return c, err
}

// Asked records a verified organization's request. If our admin had already
// asked them with the same key, the connection is made.
func (s *Store) Asked(o proto.OrgDoc) (Connection, error) {
	now := s.now().Unix()
	var c Connection
	err := s.db.Update(func(tx *bolt.Tx) error {
		existing, err := get[Connection](tx, bucketConnections, o.Domain)
		switch {
		case err == ErrNotFound:
			n := 0
			_ = tx.Bucket(bucketConnections).ForEach(func(_, v []byte) error {
				var x Connection
				if json.Unmarshal(v, &x) == nil && x.State == Incoming {
					n++
				}
				return nil
			})
			if n >= MaxIncoming {
				return ErrRefused
			}
			c = Connection{Domain: o.Domain, Name: o.Name, Server: o.Server, Key: o.Key, State: Incoming, Created: now}
		case err != nil:
			return err
		case existing.Key != o.Key:
			return ErrRefused
		case existing.State == Outgoing:
			c = existing
			c.State = Connected
		case existing.State == Incoming, existing.State == Connected:
			c = existing
		default:
			return ErrRefused
		}
		c.Updated, c.Checked = now, now
		return put(tx, bucketConnections, c.Domain, c)
	})
	return c, err
}

// Accept makes an incoming request a connection.
func (s *Store) Accept(domain string) (Connection, error) {
	return s.change(domain, func(c *Connection) error {
		if c.State != Incoming {
			return ErrRefused
		}
		c.State = Connected
		return nil
	})
}

// Accepted records the partner's acceptance of our request.
func (s *Store) Accepted(domain string) (Connection, error) {
	return s.change(domain, func(c *Connection) error {
		if c.State != Outgoing && c.State != Connected {
			return ErrRefused
		}
		c.State = Connected
		return nil
	})
}

// KeyMismatch pauses a connection whose partner now shows another key.
func (s *Store) KeyMismatch(o proto.OrgDoc) error {
	_, err := s.change(o.Domain, func(c *Connection) error {
		if c.Key == o.Key {
			return ErrRefused
		}
		c.State, c.NewKey, c.NewName, c.NewServer = KeyChanged, o.Key, o.Name, o.Server
		return nil
	})
	return err
}

// TrustNewKey accepts the partner's new key after our admin reviewed it.
func (s *Store) TrustNewKey(domain, key string) (Connection, error) {
	return s.change(domain, func(c *Connection) error {
		if c.State != KeyChanged || c.NewKey != key {
			return ErrRefused
		}
		c.Key, c.Name, c.Server = c.NewKey, c.NewName, c.NewServer
		c.NewKey, c.NewName, c.NewServer, c.State = "", "", "", Connected
		return nil
	})
}

// Checked records a successful re-check of a partner.
func (s *Store) Checked(o proto.OrgDoc) error {
	_, err := s.change(o.Domain, func(c *Connection) error {
		if c.Key != o.Key {
			return ErrRefused
		}
		c.Name, c.Server = o.Name, o.Server
		return nil
	})
	return err
}

func (s *Store) change(domain string, f func(*Connection) error) (Connection, error) {
	var c Connection
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		c, err = get[Connection](tx, bucketConnections, domain)
		if err != nil {
			return err
		}
		if err := f(&c); err != nil {
			return err
		}
		c.Updated, c.Checked = s.now().Unix(), s.now().Unix()
		return put(tx, bucketConnections, domain, c)
	})
	return c, err
}

// Disconnect removes a partner and its cached directory.
func (s *Store) Disconnect(domain string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketConnections).Get([]byte(domain)) == nil {
			return ErrNotFound
		}
		_ = tx.Bucket(bucketDirectory).Delete([]byte(domain))
		return tx.Bucket(bucketConnections).Delete([]byte(domain))
	})
}

type directoryEntry struct {
	Fetched int64          `json:"fetched"`
	People  []proto.Person `json:"people"`
}

// SetDirectory caches a partner's people.
func (s *Store) SetDirectory(domain string, people []proto.Person) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return put(tx, bucketDirectory, domain, directoryEntry{Fetched: s.now().Unix(), People: people})
	})
}

// Directory returns a partner's cached people and when they were fetched.
func (s *Store) Directory(domain string) ([]proto.Person, time.Time, error) {
	var d directoryEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		d, err = get[directoryEntry](tx, bucketDirectory, domain)
		return err
	})
	return d.People, time.Unix(d.Fetched, 0), err
}

// DropDirectory forgets a partner's cached people, so they are read again.
func (s *Store) DropDirectory(domain string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDirectory).Delete([]byte(domain))
	})
}
