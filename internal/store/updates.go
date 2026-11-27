package store

import (
	bolt "go.etcd.io/bbolt"
)

// The one update setting: whether the server asks GitHub once a day if a newer
// release exists. Off unless an admin turned it on: a missing, unreadable or
// odd value is off, because the check that asks someone else something is the
// one that has to be chosen.
var updatesDailyKey = []byte("updates-daily")

// UpdatesDaily reports whether the daily update check is on.
func (s *Store) UpdatesDaily() bool {
	on := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		on = string(tx.Bucket(bucketMeta).Get(updatesDailyKey)) == "on"
		return nil
	})
	return on
}

// SetUpdatesDaily turns the daily update check on or off.
func (s *Store) SetUpdatesDaily(on bool) error {
	value := []byte("off")
	if on {
		value = []byte("on")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(updatesDailyKey, value)
	})
}
