package server

import (
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
)

// reportReasons are the reasons a person can give, in the app's words.
var reportReasons = map[string]string{
	"spam":    "Spam",
	"abuse":   "Harassment or abuse",
	"illegal": "Something illegal",
	"other":   "Something else",
}

// maxReportNote is how long a person's note to their admin may be.
const maxReportNote = 1000

// cleanNote trims a note and refuses control characters other than new lines.
func cleanNote(note string) (string, bool) {
	note = strings.TrimSpace(note)
	if !utf8.ValidString(note) || utf8.RuneCountInString(note) > maxReportNote {
		return "", false
	}
	for _, r := range note {
		if r != '\n' && (unicode.IsControl(r) || r == '\u2028' || r == '\u2029') {
			return "", false
		}
	}
	return note, true
}

// report lets a person tell their own admin about someone they talk to. It
// carries a reason and the person's own words; the messages themselves stay
// encrypted between the two people and are never sent.
func (s *Server) report(w http.ResponseWriter, r *http.Request, c clientSession) {
	if !s.allow(r, "report|"+c.user, 5) {
		fail(w, http.StatusTooManyRequests, "Too many reports at once. Try again in a minute.")
		return
	}
	var in struct {
		About  string `json:"about"`
		Reason string `json:"reason"`
		Note   string `json:"note"`
	}
	if readJSON(r, 16<<10, &in) != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	o, _, ok := s.org()
	if !ok {
		fail(w, http.StatusServiceUnavailable, "Refused.")
		return
	}
	if _, _, err := proto.Address(in.About); err != nil {
		fail(w, http.StatusBadRequest, "Choose someone from your list.")
		return
	}
	if in.About == c.user+"@"+o.Domain {
		fail(w, http.StatusBadRequest, "You cannot report yourself.")
		return
	}
	if _, ok := reportReasons[in.Reason]; !ok {
		fail(w, http.StatusBadRequest, "Choose a reason.")
		return
	}
	note, ok := cleanNote(in.Note)
	if !ok {
		fail(w, http.StatusBadRequest, "The note can be up to 1,000 characters of plain text.")
		return
	}
	rep, err := s.st.AddReport(store.Report{From: c.user, About: in.About, Reason: in.Reason, Note: note})
	if errors.Is(err, store.ErrFull) {
		fail(w, http.StatusServiceUnavailable, "Your admin has too many open reports. Tell them directly.")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "Refused.")
		return
	}
	s.log.Info("report received", "from", c.user, "reason", in.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"id": rep.ID})
}

type reportView struct {
	store.Report
	Note       string `json:"note,omitempty"`
	FromName   string `json:"fromName"`
	AboutName  string `json:"aboutName,omitempty"`
	AboutOrg   string `json:"aboutOrg,omitempty"`
	AboutHere  bool   `json:"aboutHere"`
	AboutUser  string `json:"aboutUser,omitempty"`
	ReasonText string `json:"reasonText"`
}

// reportsList shows reports with the names the admin knows them by.
func (s *Server) reportsList(w http.ResponseWriter, _ *http.Request, _ string) {
	reports, err := s.st.Reports()
	if err != nil {
		fail(w, http.StatusInternalServerError, "Refused.")
		return
	}
	o, _, _ := s.org()
	names := map[string]string{}
	people, _ := s.st.People()
	for _, p := range people {
		names[p.Username+"@"+o.Domain] = p.Name
	}
	orgs := map[string]string{o.Domain: o.Name}
	conns, _ := s.st.Connections()
	for _, c := range conns {
		orgs[c.Domain] = c.Name
		cached, _, _ := s.st.Directory(c.Domain)
		for _, p := range cached {
			names[p.Address] = p.Name
		}
	}
	out := []reportView{}
	for _, rep := range reports {
		user, domain, _ := proto.Address(rep.About)
		v := reportView{Report: rep, Note: rep.Note, FromName: names[rep.From+"@"+o.Domain], AboutName: names[rep.About],
			AboutOrg: orgs[domain], AboutHere: domain == o.Domain, ReasonText: reportReasons[rep.Reason]}
		if v.AboutHere {
			v.AboutUser = user
		}
		if v.FromName == "" {
			v.FromName = rep.From
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// reportsClose marks a report handled.
func (s *Server) reportsClose(w http.ResponseWriter, r *http.Request, admin string) {
	var in struct {
		ID string `json:"id"`
	}
	if readJSON(r, 4<<10, &in) != nil || len(in.ID) != 32 {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	switch err := s.st.CloseReport(in.ID, admin); {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "That report is gone.")
	case errors.Is(err, store.ErrRefused):
		fail(w, http.StatusConflict, "That report was already handled.")
	case err != nil:
		fail(w, http.StatusInternalServerError, "Refused.")
	default:
		s.log.Info("report handled", "admin", admin)
		writeJSON(w, http.StatusOK, map[string]any{})
	}
}

// openReports counts reports no admin has handled yet.
func (s *Server) openReports() int {
	reports, _ := s.st.Reports()
	n := 0
	for _, r := range reports {
		if r.Closed == 0 {
			n++
		}
	}
	return n
}
