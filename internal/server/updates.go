package server

import (
	"net/http"

	"github.com/denyfirst/mohur/internal/updates"
)

// SetUpdates gives the admin pages the update service. Without one (the lab
// and tests that do not need it) the Server page says checks are not set up.
func (s *Server) SetUpdates(u *updates.Service) { s.updates = u }

// updateView is what the Server page shows.
type updateView struct {
	updates.State
	Available bool   `json:"available"`
	Release   string `json:"release,omitempty"` // the latest release's page
	Command   string `json:"command"`
}

func (s *Server) updateView(st updates.State) updateView {
	v := updateView{State: st, Available: s.updates != nil, Command: "sudo mohurd upgrade"}
	if st.Latest != "" {
		v.Release = updates.Releases + "tag/" + st.Latest
	}
	return v
}

// updatesState tells the page what runs here and what a check last found. It
// asks no one.
func (s *Server) updatesState(w http.ResponseWriter, _ *http.Request, _ string) {
	if s.updates == nil {
		writeJSON(w, http.StatusOK, s.updateView(updates.State{}))
		return
	}
	writeJSON(w, http.StatusOK, s.updateView(s.updates.State()))
}

// updatesCheck asks GitHub for the latest signed release list, at most once a
// minute however often it is pressed.
func (s *Server) updatesCheck(w http.ResponseWriter, r *http.Request, admin string) {
	if s.updates == nil {
		fail(w, http.StatusNotFound, "Update checks are not set up on this server.")
		return
	}
	st := s.updates.CheckNow(r.Context())
	if st.Tampered {
		s.log.Warn("the release list GitHub served does not verify", "admin", admin)
	}
	writeJSON(w, http.StatusOK, s.updateView(st))
}

// updatesDaily turns the daily check on or off.
func (s *Server) updatesDaily(w http.ResponseWriter, r *http.Request, admin string) {
	var in struct {
		Daily *bool `json:"daily"`
	}
	if readJSON(r, 1<<10, &in) != nil || in.Daily == nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	if s.updates == nil {
		fail(w, http.StatusNotFound, "Update checks are not set up on this server.")
		return
	}
	if err := s.updates.SetDaily(*in.Daily); err != nil {
		fail(w, http.StatusInternalServerError, "Refused.")
		return
	}
	s.log.Info("daily update check changed", "admin", admin, "on", *in.Daily)
	st := s.updates.State()
	// Turning it on checks at once, so the page has an answer to show.
	if *in.Daily {
		st = s.updates.CheckNow(r.Context())
	}
	writeJSON(w, http.StatusOK, s.updateView(st))
}

// newerRelease is the latest release when it is newer than this server, for
// the notice on every page; it asks no one.
func (s *Server) newerRelease() string {
	if s.updates == nil {
		return ""
	}
	if st := s.updates.State(); st.Newer {
		return st.Latest
	}
	return ""
}
