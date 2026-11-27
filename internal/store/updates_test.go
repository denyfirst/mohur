package store

import (
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestTheDailyUpdateCheckIsOffUntilChosen(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "instance.key")
	s, err := Open(dir, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if s.UpdatesDaily() {
		t.Fatal("a new server checks daily")
	}
	if err := s.SetUpdatesDaily(true); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s, err = Open(dir, keyFile); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if !s.UpdatesDaily() {
		t.Fatal("the choice did not survive a restart")
	}
	// Anything but "on" is off.
	for _, v := range []string{"", "On", "true", "1", "on "} {
		_ = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put(updatesDailyKey, []byte(v)) })
		if s.UpdatesDaily() {
			t.Fatalf("%q reads as on", v)
		}
	}
	if err := s.SetUpdatesDaily(false); err != nil || s.UpdatesDaily() {
		t.Fatal("turning it off did not hold")
	}
}
