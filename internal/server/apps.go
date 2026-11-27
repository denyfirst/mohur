package server

import (
	"net/http"
	"regexp"
	"strconv"
)

// OldestApp is the oldest desktop app this server works with. Raise it only
// when a change needs a newer app, and only once that app is in the Microsoft
// Store, so no one is asked to update to an app they cannot get yet.
const OldestApp = "0.1.0"

// AppHeader carries the app's version when it joins and signs in. It is what
// the app says about itself: it decides whom to ask to update, never whom to
// trust. It goes to the person's own server only, and partners never see it.
const AppHeader = "Mohur-App"

var appVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)

// parseApp reads an app version such as 0.1.0.
func parseApp(v string) ([3]int, bool) {
	m := appVersionRE.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, true
}

// appOlder reports whether app version a comes before b. Both are valid.
func appOlder(a, b string) bool {
	x, _ := parseApp(a)
	y, _ := parseApp(b)
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

// oldestApp is OldestApp, or what a test set.
func (s *Server) oldestApp() string { return *s.oldest.Load() }

// setOldestApp raises or lowers the oldest app; tests only.
func (s *Server) setOldestApp(v string) { s.oldest.Store(&v) }

// appVersion reads the version the app gave. An app too old for this server,
// or one that gives none, is asked to update; a malformed version is refused.
// On false the answer has been written.
func (s *Server) appVersion(w http.ResponseWriter, r *http.Request) (string, bool) {
	vals := r.Header.Values(AppHeader)
	if len(vals) > 1 {
		fail(w, http.StatusBadRequest, "Refused.")
		return "", false
	}
	oldest := s.oldestApp()
	if len(vals) == 1 {
		if _, ok := parseApp(vals[0]); !ok {
			fail(w, http.StatusBadRequest, "Refused.")
			return "", false
		}
		if !appOlder(vals[0], oldest) {
			return vals[0], true
		}
	}
	fail(w, http.StatusUpgradeRequired, "This Mohur app is too old for your organization's server. Update Mohur to "+oldest+" or newer, then open it again.")
	return "", false
}
