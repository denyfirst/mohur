package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestReportNotesAreSealedAndReportsCapped(t *testing.T) {
	s, _, _ := setUpAdmin(t, "a long enough admin password")
	now := time.Now()
	s.SetClock(func() time.Time { return now })

	const note = "He keeps sending contract drafts I never asked for."
	r, err := s.AddReport(Report{From: "aylin", About: "kamran@beta.e2e.test", Reason: "spam", Note: note})
	if err != nil || len(r.ID) != 32 || r.At != now.Unix() {
		t.Fatalf("add: %+v, %v", r, err)
	}
	// The note is sealed on disk; the rest is not secret.
	err = s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketReports).Get([]byte(r.ID))
		if raw == nil || bytes.Contains(raw, []byte("contract drafts")) {
			t.Fatalf("stored record: %q", raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.Reports()
	if err != nil || len(list) != 1 || list[0].Note != note || list[0].From != "aylin" {
		t.Fatalf("read back: %+v, %v", list, err)
	}
	// A sealed note moved to another report does not open.
	other, _ := s.AddReport(Report{From: "murad", About: "aylin@alpha.e2e.test", Reason: "other"})
	_ = s.db.Update(func(tx *bolt.Tx) error {
		a, _ := get[reportRecord](tx, bucketReports, r.ID)
		b, _ := get[reportRecord](tx, bucketReports, other.ID)
		b.Note = a.Note
		return put(tx, bucketReports, other.ID, b)
	})
	if _, err := s.Reports(); err == nil {
		t.Fatal("a note moved between reports opened")
	}
	_ = s.db.Update(func(tx *bolt.Tx) error {
		b, _ := get[reportRecord](tx, bucketReports, other.ID)
		b.Note = nil
		return put(tx, bucketReports, other.ID, b)
	})

	// Closing: once, and only an existing report.
	if err := s.CloseReport(r.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseReport(r.ID, "admin"); !errors.Is(err, ErrRefused) {
		t.Fatalf("closed twice: %v", err)
	}
	if err := s.CloseReport("nope", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown report: %v", err)
	}

	// Open reports are capped; a handled one does not count.
	for i := 1; i < MaxOpenReports; i++ { // "other" is already open
		if _, err := s.AddReport(Report{From: "murad", About: "aylin@alpha.e2e.test", Reason: "spam"}); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	if _, err := s.AddReport(Report{From: "murad", About: "aylin@alpha.e2e.test", Reason: "spam"}); !errors.Is(err, ErrFull) {
		t.Fatalf("over the cap: %v", err)
	}

	// Handling one frees a place. Handled reports go after ReportKeep; the
	// one just handled and every open one stay.
	now = now.Add(ReportKeep + time.Hour)
	if err := s.CloseReport(other.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddReport(Report{From: "murad", About: "aylin@alpha.e2e.test", Reason: "spam"}); err != nil {
		t.Fatalf("after handling one: %v", err)
	}
	list, _ = s.Reports()
	open := 0
	for _, x := range list {
		if x.ID == r.ID {
			t.Fatal("a report handled long ago was kept")
		}
		if x.Closed == 0 {
			open++
		}
	}
	if open != MaxOpenReports || len(list) != MaxOpenReports+1 || list[len(list)-1].ID != other.ID {
		t.Fatalf("%d reports kept (%d open), want %d with the handled one last", len(list), open, MaxOpenReports+1)
	}
}
