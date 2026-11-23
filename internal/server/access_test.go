package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
)

func (d *device) contacts(fresh bool) (addresses []string, orgs []string) {
	var res struct {
		People []proto.Person `json:"people"`
		Orgs   []orgView      `json:"orgs"`
	}
	path := "/api/v1/contacts"
	if fresh {
		path += "?fresh=1"
	}
	d.call("GET", path, nil, &res, 200)
	for _, p := range res.People {
		addresses = append(addresses, p.Address)
	}
	for _, o := range res.Orgs {
		orgs = append(orgs, o.Domain)
	}
	return addresses, orgs
}

func (d *device) send(to *device, want int) {
	d.org.lab.t.Helper()
	d.call("POST", "/api/v1/send", map[string]any{"envelopes": []map[string]any{{"to": to.address, "toDevice": to.id, "type": 2, "body": randomB64(64, 0)}}}, nil, want)
}

func (o *org) access(domain string, people []string, want int) {
	o.lab.t.Helper()
	o.adminCall("partners/access", map[string]any{"domain": domain, "people": people}, nil, want)
}

// inviteFor invites a person who may write with the given partners.
func (o *org) inviteFor(username, name string, partners ...string) string {
	o.lab.t.Helper()
	var res struct {
		Invite string `json:"invite"`
	}
	o.adminCall("people/invite", map[string]any{"username": username, "name": name, "partners": append([]string{}, partners...)}, &res, 200)
	return res.Invite
}

func (o *org) setPartners(username string, partners []string, want int) {
	o.lab.t.Helper()
	o.adminCall("people/partners", map[string]any{"username": username, "partners": partners}, nil, want)
}

func (o *org) personPartners(username string) []string {
	o.lab.t.Helper()
	var people []personView
	o.adminCall("people", nil, &people, 200)
	for _, p := range people {
		if p.Username == username {
			return p.Partners
		}
	}
	o.lab.t.Fatalf("%s is not on the People page", username)
	return nil
}

func TestPartnerAccessLimitsWhoCanWrite(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	aylin := alpha.join(alpha.invite("aylin", "Aylin"), 200)
	murad := alpha.join(alpha.invite("murad", "Murad"), 200)
	kamran := beta.join(beta.invite("kamran", "Kamran"), 200)
	connect(t, alpha, beta)

	// No one, until each side chooses its own people.
	if got, orgs := kamran.contacts(true); slices.Contains(got, aylin.address) || slices.Contains(got, murad.address) || slices.Contains(orgs, "alpha.e2e.test") {
		t.Fatalf("before choosing, kamran sees %v %v", got, orgs)
	}
	if got, orgs := aylin.contacts(true); slices.Contains(got, kamran.address) || slices.Contains(orgs, "beta.e2e.test") {
		t.Fatalf("before choosing, aylin sees %v %v", got, orgs)
	}
	murad.send(kamran, 403)
	beta.access("alpha.e2e.test", []string{"kamran"}, 200)
	murad.send(kamran, 403) // Alpha has not chosen Murad
	if got, _ := kamran.contacts(true); slices.Contains(got, aylin.address) || slices.Contains(got, murad.address) {
		t.Fatalf("with only beta's choice, kamran sees %v", got)
	}

	// Alpha lets only Aylin write with Beta.
	alpha.access("beta.e2e.test", []string{"aylin", "aylin"}, 200)
	var partners []partnerView
	alpha.adminCall("partners", nil, &partners, 200)
	if len(partners) != 1 || !slices.Equal(partners[0].People, []string{"aylin"}) || partners[0].Theirs == nil || *partners[0].Theirs != 1 {
		t.Fatalf("partners = %+v", partners)
	}
	if got := alpha.personPartners("aylin"); !slices.Equal(got, []string{"Beta LLC"}) {
		t.Fatalf("aylin writes with %v", got)
	}
	if got := alpha.personPartners("murad"); len(got) != 0 {
		t.Fatalf("murad writes with %v", got)
	}

	// Murad no longer sees Beta and cannot reach it in any way.
	if people, orgs := murad.contacts(true); slices.Contains(people, kamran.address) || slices.Contains(orgs, "beta.e2e.test") {
		t.Fatalf("murad still sees %v %v", people, orgs)
	}
	murad.call("GET", "/api/v1/keys?address="+kamran.address, nil, nil, 403)
	murad.send(kamran, 403)
	req, _ := http.NewRequest("POST", alpha.url("/api/v1/blobs?to="+kamran.address), bytes.NewReader([]byte("ciphertext")))
	req.Header.Set("Authorization", "Bearer "+murad.token)
	if resp, err := murad.http.Do(req); err != nil || resp.StatusCode != 400 {
		t.Fatalf("murad's upload to beta: %v %v", resp.StatusCode, err)
	}
	// Colleagues still see each other.
	if people, _ := murad.contacts(false); !slices.Contains(people, aylin.address) {
		t.Fatalf("murad lost his colleague: %v", people)
	}
	murad.send(aylin, 200)

	// Aylin still can.
	if people, _ := aylin.contacts(true); !slices.Contains(people, kamran.address) {
		t.Fatalf("aylin lost beta: %v", people)
	}
	aylin.call("GET", "/api/v1/keys?address="+kamran.address, nil, nil, 200)
	aylin.send(kamran, 200)

	// Beta sees only Aylin, and Alpha refuses anything for Murad from Beta.
	if people, _ := kamran.contacts(true); !slices.Contains(people, aylin.address) || slices.Contains(people, murad.address) {
		t.Fatalf("kamran sees %v", people)
	}
	kamran.call("GET", "/api/v1/keys?address="+murad.address, nil, nil, 404)
	kamran.send(murad, 403)
	kamran.send(aylin, 200)

	// Beta's server, bypassing its own checks, is refused by Alpha's.
	env := proto.Envelope{ID: randomID(), From: kamran.address, FromDevice: kamran.id, FromCert: kamran.cert, To: murad.address, ToDevice: murad.id, Type: 2, Body: randomB64(64, 0)}
	body, _ := json.Marshal(map[string]any{"envelopes": []proto.Envelope{env}})
	if s := fedRaw(t, beta, alpha, "POST", "/fed/v1/deliver", body, nil); s != 404 {
		t.Fatalf("raw delivery to murad: %d", s)
	}
	if s := fedRaw(t, beta, alpha, "GET", "/fed/v1/keys?user=murad", nil, nil); s != 404 {
		t.Fatalf("raw keys of murad: %d", s)
	}
	if s := fedRaw(t, beta, alpha, "PUT", "/fed/v1/blobs/"+randomID()+"?from="+kamran.address+"&to="+murad.address, []byte("ciphertext"), nil); s != 404 {
		t.Fatalf("raw file to murad: %d", s)
	}
	var dir []proto.Person
	if err := beta.srv.fedCall(t.Context(), mustConnection(t, beta, "alpha.e2e.test"), "GET", "/fed/v1/directory", nil, &dir); err != nil || len(dir) != 1 || dir[0].Address != aylin.address {
		t.Fatalf("alpha's directory for beta = %+v, %v", dir, err)
	}

	// The People page chooses the same thing from the person's side.
	alpha.setPartners("murad", []string{"beta.e2e.test"}, 200)
	if c := mustConnection(t, alpha, "beta.e2e.test"); !slices.Equal(c.People, []string{"aylin", "murad"}) {
		t.Fatalf("after choosing murad's partners: %+v", c)
	}
	murad.send(kamran, 200)
	if got := alpha.personPartners("murad"); !slices.Equal(got, []string{"Beta LLC"}) {
		t.Fatalf("murad writes with %v", got)
	}
	alpha.setPartners("murad", []string{}, 200)
	murad.send(kamran, 403)
	if c := mustConnection(t, alpha, "beta.e2e.test"); !slices.Equal(c.People, []string{"aylin"}) {
		t.Fatalf("after taking murad off: %+v", c)
	}
}

func TestNewPeopleAreNotShownToPartnersUnlessChosen(t *testing.T) {
	l := newLab(t)
	alpha, beta, gamma := l.start("alpha.e2e.test"), l.start("beta.e2e.test"), l.start("gamma.e2e.test")
	kamran := beta.join(beta.invite("kamran", "Kamran"), 200)
	samir := gamma.join(gamma.invite("samir", "Samir"), 200)
	connect(t, alpha, beta)
	connect(t, alpha, gamma)
	beta.access("alpha.e2e.test", []string{"kamran"}, 200)
	gamma.access("alpha.e2e.test", []string{"samir"}, 200)

	// A plain invite shows the new person to no partner.
	nigar := alpha.join(alpha.invite("nigar", "Nigar"), 200)
	if got, _ := kamran.contacts(true); slices.Contains(got, nigar.address) {
		t.Fatalf("kamran sees a new person nobody chose: %v", got)
	}
	nigar.send(kamran, 403)

	// An invite can choose the partners at once.
	var inv struct {
		Invite string `json:"invite"`
	}
	alpha.adminCall("people/invite", map[string]any{"username": "leyla", "name": "Leyla", "partners": []string{"gamma.e2e.test"}}, &inv, 200)
	leyla := alpha.join(inv.Invite, 200)
	if got, _ := samir.contacts(true); !slices.Contains(got, leyla.address) {
		t.Fatalf("samir does not see leyla: %v", got)
	}
	if got, _ := kamran.contacts(true); slices.Contains(got, leyla.address) {
		t.Fatalf("kamran sees leyla: %v", got)
	}
	leyla.send(samir, 200)
	leyla.send(kamran, 403)

	// A renewed invite without a partner list keeps the person's partners;
	// with one, it replaces them.
	alpha.adminCall("people/invite", map[string]any{"username": "rauf", "name": "Rauf", "partners": []string{"beta.e2e.test", "gamma.e2e.test"}}, nil, 200)
	alpha.adminCall("people/invite", map[string]any{"username": "rauf", "name": "Rauf"}, nil, 200)
	var people []personView
	alpha.adminCall("people", nil, &people, 200)
	found := false
	for _, p := range people {
		if p.Username == "rauf" {
			found = true
			if !slices.Equal(p.PartnerDomains, []string{"beta.e2e.test", "gamma.e2e.test"}) {
				t.Fatalf("renewed invite: %+v", p)
			}
		}
	}
	if !found {
		t.Fatal("rauf is not on the People page")
	}
	alpha.adminCall("people/invite", map[string]any{"username": "rauf", "name": "Rauf", "partners": []string{}}, nil, 200)
	if c := mustConnection(t, alpha, "beta.e2e.test"); slices.Contains(c.People, "rauf") {
		t.Fatalf("an invite with no partners kept rauf on beta: %v", c.People)
	}

	// An unknown partner refuses the whole invite.
	alpha.adminCall("people/invite", map[string]any{"username": "ghost", "name": "Ghost", "partners": []string{"omega.e2e.test"}}, nil, 400)
	alpha.adminCall("people/invite", map[string]any{"username": "ghost", "name": "Ghost", "partners": []string{"not a domain"}}, nil, 400)
	alpha.adminCall("people", nil, &people, 200)
	for _, p := range people {
		if p.Username == "ghost" {
			t.Fatal("a refused invite created the person")
		}
	}

	// The partner choices are every partner, without contacting them.
	var choices []struct{ Domain, Name, State string }
	alpha.adminCall("partners/choices", nil, &choices, 200)
	if len(choices) != 2 || choices[0].Name != "Beta LLC" || choices[1].State != store.Connected {
		t.Fatalf("choices = %+v", choices)
	}
}

func TestPersonPartnersRefuseBadInput(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	alpha.join(alpha.invite("aylin", "Aylin"), 200)
	connect(t, alpha, beta)

	alpha.setPartners("nobody", []string{"beta.e2e.test"}, 404)
	alpha.setPartners("aylin", []string{"omega.e2e.test"}, 400)
	alpha.setPartners("aylin", []string{"not a domain"}, 400)
	alpha.setPartners("Aylin Bad", []string{"beta.e2e.test"}, 400)
	alpha.adminCall("people/partners", "not an object", nil, 400)
	many := make([]string, 1001)
	for i := range many {
		many[i] = "beta.e2e.test"
	}
	alpha.setPartners("aylin", many, 400)
	if c := mustConnection(t, alpha, "beta.e2e.test"); len(c.People) != 0 {
		t.Fatalf("a refused change was saved: %+v", c)
	}
	// Cross-site and signed-out calls are refused like every admin call.
	body := []byte(`{"username":"aylin","partners":["beta.e2e.test"]}`)
	req, _ := http.NewRequest("POST", alpha.url("/admin/api/people/partners"), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+alpha.server)
	alpha.do(req, nil, 403)
	req, _ = http.NewRequest("POST", alpha.url("/admin/api/people/partners"), bytes.NewReader(body))
	req.Header.Set("X-Mohur", "1")
	req.Header.Set("Content-Type", "application/json")
	if resp, err := l.client(nil).Do(req); err != nil || resp.StatusCode != 401 {
		t.Fatalf("signed-out partner change: %v %v", resp.StatusCode, err)
	}
	if c := mustConnection(t, alpha, "beta.e2e.test"); len(c.People) != 0 {
		t.Fatalf("a refused change was saved: %+v", c)
	}
}

func mustConnection(t *testing.T, o *org, domain string) store.Connection {
	t.Helper()
	c, err := o.st.Connection(domain)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRemovedPersonsAccessIsNotInherited(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	alpha.join(alpha.invite("aylin", "Aylin"), 200)
	alpha.join(alpha.invite("murad", "Murad"), 200)
	kamran := beta.join(beta.invite("kamran", "Kamran"), 200)
	connect(t, alpha, beta)
	alpha.access("beta.e2e.test", []string{"aylin", "murad"}, 200)

	alpha.adminCall("people/remove", map[string]any{"username": "murad"}, nil, 200)
	if c := mustConnection(t, alpha, "beta.e2e.test"); !slices.Equal(c.People, []string{"aylin"}) {
		t.Fatalf("after removing murad: %v", c.People)
	}
	// Someone new with the same user name starts without access.
	other := alpha.join(alpha.invite("murad", "Another Murad"), 200)
	other.send(kamran, 403)
}

func TestPartnerAccessRefusesBadInput(t *testing.T) {
	l := newLab(t)
	alpha, beta := l.start("alpha.e2e.test"), l.start("beta.e2e.test")
	alpha.join(alpha.invite("aylin", "Aylin"), 200)
	connect(t, alpha, beta)
	alpha.access("beta.e2e.test", []string{"aylin"}, 200)

	alpha.access("gamma.e2e.test", []string{"aylin"}, 404)    // not a partner
	alpha.access("not a domain", []string{"aylin"}, 400)      // malformed domain
	alpha.access("beta.e2e.test", []string{"Aylin Bad"}, 400) // malformed user name
	alpha.access("beta.e2e.test", []string{"nobody"}, 400)    // not a person here
	alpha.access("beta.e2e.test", []string{"kamran"}, 400)    // the partner's person
	many := make([]string, store.MaxChosen+1)
	for i := range many {
		many[i] = fmt.Sprintf("u%d", i)
	}
	alpha.access("beta.e2e.test", many, 400)
	alpha.adminCall("partners/access", "not an object", nil, 400)
	if c := mustConnection(t, alpha, "beta.e2e.test"); !slices.Equal(c.People, []string{"aylin"}) {
		t.Fatalf("a refused change was saved: %+v", c)
	}

	// Cross-site and signed-out calls are refused like every admin call.
	req, _ := http.NewRequest("POST", alpha.url("/admin/api/partners/access"), bytes.NewReader([]byte(`{"domain":"beta.e2e.test","people":[]}`)))
	req.Header.Set("Origin", "https://"+alpha.server)
	alpha.do(req, nil, 403)
	req, _ = http.NewRequest("POST", alpha.url("/admin/api/partners/access"), bytes.NewReader([]byte(`{"domain":"beta.e2e.test","people":[]}`)))
	req.Header.Set("X-Mohur", "1")
	if resp, err := l.client(nil).Do(req); err != nil || resp.StatusCode != 401 {
		t.Fatalf("signed-out access change: %v %v", resp.StatusCode, err)
	}
	if c := mustConnection(t, alpha, "beta.e2e.test"); !slices.Equal(c.People, []string{"aylin"}) {
		t.Fatalf("a refused change was saved: %+v", c)
	}
	// Choosing no one is allowed: nobody here can write with the partner.
	alpha.access("beta.e2e.test", []string{}, 200)
	if c := mustConnection(t, alpha, "beta.e2e.test"); len(c.People) != 0 {
		t.Fatalf("no one chosen: %+v", c)
	}
}

type inboxAnswer struct {
	Envelopes []proto.Envelope `json:"envelopes"`
	Directory int64            `json:"directory"`
}

func TestAppsHearOfChangesAtOnce(t *testing.T) {
	l := newLab(t)
	alpha, beta, gamma := l.start("alpha.e2e.test"), l.start("beta.e2e.test"), l.start("gamma.e2e.test")
	aylin := alpha.join(alpha.invite("aylin", "Aylin"), 200)
	kamran := beta.join(beta.invite("kamran", "Kamran"), 200)

	var before inboxAnswer
	aylin.call("GET", "/api/v1/inbox", nil, &before, 200)

	// A waiting app returns as soon as its organization connects a partner.
	done := make(chan inboxAnswer, 1)
	go func() {
		var res inboxAnswer
		aylin.call("GET", "/api/v1/inbox?wait=1", nil, &res, 200)
		done <- res
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	connect(t, alpha, beta)
	select {
	case res := <-done:
		if res.Directory <= before.Directory || time.Since(start) > 10*time.Second {
			t.Fatalf("woken with %d after %v, had %d", res.Directory, time.Since(start), before.Directory)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the waiting app was not woken by the new partner")
	}

	// A person joining Alpha reaches Beta's apps without waiting for the
	// minute: Alpha tells Beta, which forgets its cached copy of Alpha.
	beta.access("alpha.e2e.test", []string{"kamran"}, 200)
	var seen inboxAnswer
	kamran.call("GET", "/api/v1/inbox", nil, &seen, 200)
	waitForNotice := func(what string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var now inboxAnswer
			kamran.call("GET", "/api/v1/inbox", nil, &now, 200)
			if now.Directory > seen.Directory {
				seen = now
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("beta was not told " + what)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// Choosing Nigar for Beta in her invite is itself a change Beta hears of.
	invite := alpha.inviteFor("nigar", "Nigar", "beta.e2e.test")
	waitForNotice("that nigar was chosen")
	if people, _ := kamran.contacts(true); slices.Contains(people, "nigar@alpha.e2e.test") {
		t.Fatal("nigar listed before joining")
	}
	alpha.join(invite, 200)
	waitForNotice("that alpha's people changed")
	if people, _ := kamran.contacts(false); !slices.Contains(people, "nigar@alpha.e2e.test") {
		t.Fatalf("kamran does not see nigar yet: %v", people)
	}

	// Only a connected partner, signing with its pinned key, can say so.
	if s := fedRaw(t, gamma, beta, "POST", "/fed/v1/changed", []byte("{}"), nil); s != 403 {
		t.Fatalf("stranger's change notice: %d", s)
	}
	if s := fedRaw(t, alpha, beta, "POST", "/fed/v1/changed", []byte("{}"), func(r *http.Request) { r.Header.Set(hSig, r.Header.Get(hSig)[:10]+"AAAA") }); s != 403 {
		t.Fatalf("forged change notice: %d", s)
	}
	if s := fedRaw(t, alpha, beta, "POST", "/fed/v1/changed", []byte("{}"), nil); s != 200 {
		t.Fatalf("partner's change notice: %d", s)
	}
}
