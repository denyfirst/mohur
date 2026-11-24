package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
	bolt "go.etcd.io/bbolt"
)

// The privacy page promises that a server keeps an encrypted message only
// until the recipient's app collects it, and mail and files at most 30 days.
func TestMailAndFilesGoAfterThirtyDays(t *testing.T) {
	s, _, _ := setUpAdmin(t, "a long enough admin password")
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	code, _, err := s.Invite("aylin", "Aylin")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Redeem(Join{Code: code, Label: "laptop"}, func(*proto.DeviceCert) {})
	if err != nil {
		t.Fatal(err)
	}
	queued := func() int {
		t.Helper()
		n := 0
		_ = s.db.View(func(tx *bolt.Tx) error {
			if b := tx.Bucket(bucketQueue).Bucket([]byte("aylin")); b != nil {
				n = b.Stats().KeyN
			}
			return nil
		})
		return n
	}
	for _, id := range []string{"collected", "waiting"} {
		err := s.Enqueue(proto.Envelope{ID: id, From: "kamran@beta.e2e.test", To: "aylin@alpha.e2e.test",
			ToDevice: p.Device.ID, Type: proto.TypeWhisper, Body: "c2VhbGVk"})
		if err != nil {
			t.Fatal(err)
		}
	}
	file := proto.B64([]byte("sixteen byte id!"))
	if _, err := s.PutBlob(file, "kamran@beta.e2e.test", "aylin@alpha.e2e.test", strings.NewReader("sealed bytes")); err != nil {
		t.Fatal(err)
	}

	// What the app collected goes at once.
	if err := s.Ack("aylin", []string{"collected"}); err != nil {
		t.Fatal(err)
	}
	if n := queued(); n != 1 {
		t.Fatalf("after the app collected one of two: %d kept", n)
	}

	// A minute before 30 days the rest is still there.
	now = now.Add(proto.QueueLifetime - time.Minute)
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if n := queued(); n != 1 {
		t.Fatalf("uncollected mail went early: %d kept", n)
	}
	if _, err := s.Blob(file); err != nil {
		t.Fatalf("the file went early: %v", err)
	}

	// After 30 days the mail is deleted, not only hidden, and so is the file,
	// from the database and from the disk.
	now = now.Add(2 * time.Minute)
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if n := queued(); n != 0 {
		t.Fatalf("mail older than 30 days kept: %d", n)
	}
	if _, err := s.Blob(file); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a file older than 30 days kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.blobDir, file)); !os.IsNotExist(err) {
		t.Fatalf("the file's bytes stayed on disk: %v", err)
	}
}
