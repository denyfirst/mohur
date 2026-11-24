package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrFull means there are too many open reports to take another.
var ErrFull = errors.New("full")

// MaxOpenReports caps open reports, so a person cannot fill the disk.
const MaxOpenReports = 1000

// ReportKeep is how long a handled report stays on the Reports page.
const ReportKeep = 90 * 24 * time.Hour

// Report is a person telling their own admin about someone they talk to.
// It holds the reason and the person's own words, never message content:
// messages stay encrypted between the two people.
type Report struct {
	ID       string `json:"id"`
	From     string `json:"from"`  // username here
	About    string `json:"about"` // address, here or at a partner
	Reason   string `json:"reason"`
	Note     string `json:"-"`
	At       int64  `json:"at"`
	Closed   int64  `json:"closed,omitempty"`
	ClosedBy string `json:"closedBy,omitempty"`
}

type reportRecord struct {
	Report
	Note []byte `json:"note,omitempty"` // sealed
}

// AddReport stores a new report and returns it with its ID and time.
func (s *Store) AddReport(r Report) (Report, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return Report{}, err
	}
	r.ID = hex.EncodeToString(raw)
	r.At = s.now().Unix()
	r.Closed, r.ClosedBy = 0, ""
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketReports)
		open := 0
		var stale [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec reportRecord
			if err := jsonUnmarshal(v, &rec); err != nil {
				return err
			}
			switch {
			case rec.Closed == 0:
				open++
			case s.now().Sub(time.Unix(rec.Closed, 0)) > ReportKeep:
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		if open >= MaxOpenReports {
			return ErrFull
		}
		rec := reportRecord{Report: r}
		if r.Note != "" {
			rec.Note = s.seal("report/"+r.ID, []byte(r.Note))
		}
		return put(tx, bucketReports, r.ID, rec)
	})
	return r, err
}

// Reports lists reports, open ones first, newest first within each.
func (s *Store) Reports() ([]Report, error) {
	var out []Report
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketReports).ForEach(func(_, v []byte) error {
			var rec reportRecord
			if err := jsonUnmarshal(v, &rec); err != nil {
				return err
			}
			r := rec.Report
			if len(rec.Note) > 0 {
				note, err := s.open("report/"+r.ID, rec.Note)
				if err != nil {
					return err
				}
				r.Note = string(note)
			}
			out = append(out, r)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Closed == 0) != (out[j].Closed == 0) {
			return out[i].Closed == 0
		}
		return out[i].At > out[j].At
	})
	return out, err
}

// CloseReport marks a report handled by admin.
func (s *Store) CloseReport(id, admin string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		rec, err := get[reportRecord](tx, bucketReports, id)
		if err != nil {
			return err
		}
		if rec.Closed != 0 {
			return ErrRefused
		}
		rec.Closed, rec.ClosedBy = s.now().Unix(), admin
		return put(tx, bucketReports, id, rec)
	})
}
