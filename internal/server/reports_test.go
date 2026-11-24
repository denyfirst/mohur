package server

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

type reportRow struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	FromName   string `json:"fromName"`
	About      string `json:"about"`
	AboutName  string `json:"aboutName"`
	AboutOrg   string `json:"aboutOrg"`
	AboutHere  bool   `json:"aboutHere"`
	Reason     string `json:"reason"`
	ReasonText string `json:"reasonText"`
	Note       string `json:"note"`
	Closed     int64  `json:"closed"`
	ClosedBy   string `json:"closedBy"`
}

func (o *org) reports() []reportRow {
	o.lab.t.Helper()
	var out []reportRow
	o.adminCall("reports", nil, &out, 200)
	return out
}

func (o *org) openReportCount() int {
	o.lab.t.Helper()
	var st struct {
		OpenReports int `json:"openReports"`
	}
	o.adminCall("state", nil, &st, 200)
	return st.OpenReports
}

func (d *device) report(about, reason, note string, want int) string {
	d.org.lab.t.Helper()
	var res struct {
		ID string `json:"id"`
	}
	d.call("POST", "/api/v1/report", map[string]any{"about": about, "reason": reason, "note": note}, &res, want)
	return res.ID
}

func TestReportsReachOnlyTheReportersAdmin(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	connect(t, alpha, beta)
	aylin := alpha.join(alpha.inviteFor("aylin", "Aylin Məmmədova", "beta.e2e.test"), 200)
	murad := alpha.join(alpha.invite("murad", "Murad"), 200)
	kamran := beta.join(beta.inviteFor("kamran", "Kamran", "alpha.e2e.test"), 200)
	aylin.contacts(true) // Alpha learns Beta's names

	note := "Keeps sending me offers.\nI asked him to stop."
	id := aylin.report(kamran.address, "spam", "  "+note+"  ", 200)
	murad.report(aylin.address, "abuse", "", 200)
	if len(id) != 32 {
		t.Fatalf("report id %q", id)
	}
	if n := alpha.openReportCount(); n != 2 {
		t.Fatalf("open reports on Alpha: %d", n)
	}
	got := alpha.reports()
	if len(got) != 2 {
		t.Fatalf("Alpha's reports: %+v", got)
	}
	var partner, colleague reportRow
	for _, r := range got {
		if r.About == kamran.address {
			partner = r
		} else {
			colleague = r
		}
	}
	if partner.ID != id || partner.From != "aylin" || partner.FromName != "Aylin Məmmədova" || partner.AboutName != "Kamran" ||
		partner.AboutOrg != "Beta LLC" || partner.AboutHere || partner.ReasonText != "Spam" || partner.Note != note {
		t.Fatalf("report about a partner's person: %+v", partner)
	}
	if colleague.About != aylin.address || !colleague.AboutHere || colleague.Note != "" || colleague.ReasonText != "Harassment or abuse" {
		t.Fatalf("report about a colleague: %+v", colleague)
	}
	// The partner, and the person reported, hear nothing of it.
	if got := beta.reports(); len(got) != 0 || beta.openReportCount() != 0 {
		t.Fatalf("Beta sees Alpha's reports: %+v", got)
	}

	// Handling a report: once, by an existing id.
	alpha.adminCall("reports/close", map[string]any{"id": id}, nil, 200)
	alpha.adminCall("reports/close", map[string]any{"id": id}, nil, 409)
	alpha.adminCall("reports/close", map[string]any{"id": strings.Repeat("0", 32)}, nil, 404)
	alpha.adminCall("reports/close", map[string]any{"id": "short"}, nil, 400)
	beta.adminCall("reports/close", map[string]any{"id": colleague.ID}, nil, 404)
	if n := alpha.openReportCount(); n != 1 {
		t.Fatalf("open reports after handling one: %d", n)
	}
	for _, r := range alpha.reports() {
		if r.ID == id && (r.Closed == 0 || r.ClosedBy != "admin") {
			t.Fatalf("handled report: %+v", r)
		}
	}
}

func TestReportRefusals(t *testing.T) {
	l := newLab(t)
	alpha := l.start("alpha.e2e.test")
	aylin := alpha.join(alpha.invite("aylin", "Aylin"), 200)
	murad := alpha.join(alpha.invite("murad", "Murad"), 200)

	// Refused attempts count towards the limit too, so the clock moves on a
	// minute before each one here.
	clock := &testClock{t: time.Now()}
	alpha.srv.SetClock(clock.Now)
	defer alpha.srv.SetClock(time.Now)
	for _, c := range []struct{ about, reason, note string }{
		{"", "spam", ""},
		{"not an address", "spam", ""},
		{"Murad@alpha.e2e.test", "spam", ""},
		{murad.address + "\n", "spam", ""},
		{aylin.address, "spam", ""}, // yourself
		{murad.address, "", ""},
		{murad.address, "Spam", ""},
		{murad.address, "hate", ""},
		{murad.address, "other", strings.Repeat("é", 1001)},
		{murad.address, "other", "bell\a"},
		{murad.address, "other", "line\u2028break"},
	} {
		clock.Add(time.Minute)
		aylin.report(c.about, c.reason, c.note, 400)
	}
	clock.Add(time.Minute)
	aylin.report(murad.address, "other", strings.Repeat("é", 1000), 200)
	if n := alpha.openReportCount(); n != 1 {
		t.Fatalf("refused reports were stored: %d open", n)
	}

	// Not signed in.
	signedOut := *aylin
	signedOut.token = ""
	signedOut.report(murad.address, "spam", "", 401)

	// Five a minute per person, refused ones included; then the sixth waits,
	// and others are not held up.
	clock.Add(time.Minute)
	for i := 0; i < 5; i++ {
		aylin.report(murad.address, "spam", "", 200)
	}
	aylin.report(murad.address, "spam", "", 429)
	murad.report(aylin.address, "spam", "", 200)

	// The admin pages refuse cross-site calls to reports.
	for _, path := range []string{"/admin/api/reports", "/admin/api/reports/close"} {
		method := "GET"
		var body *bytes.Reader
		if strings.HasSuffix(path, "close") {
			method, body = "POST", bytes.NewReader([]byte(`{"id":"`+strings.Repeat("0", 32)+`"}`))
		} else {
			body = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, alpha.url(path), body)
		req.Header.Set("X-Mohur", "1")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.e2e.test")
		alpha.do(req, nil, 403)
	}
}
