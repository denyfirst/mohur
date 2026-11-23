package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/qrcode"
	"github.com/denyfirst/mohur/internal/store"
)

const adminCookie = "__Host-mohur-admin"

// AdminLifetime is how long an admin stays signed in.
const AdminLifetime = 8 * time.Hour

// sameOrigin refuses cross-site admin calls: the page sends a custom header a
// form or another site cannot, and the browser's Origin must be this server.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("X-Mohur") != "1" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host || u.Scheme != "https" {
			return false
		}
	}
	return r.Header.Get("Sec-Fetch-Site") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

func (s *Server) adminSession(r *http.Request) (string, bool) {
	c, err := r.Cookie(adminCookie)
	if err != nil {
		return "", false
	}
	h := sha256.Sum256([]byte(c.Value))
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[h]
	if !ok || s.now().After(a.expires) {
		delete(s.admins, h)
		return "", false
	}
	return a.username, true
}

func (s *Server) admin(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			fail(w, http.StatusForbidden, "Refused.")
			return
		}
		user, ok := s.adminSession(r)
		if !ok {
			fail(w, http.StatusUnauthorized, "Sign in again.")
			return
		}
		h(w, r, user)
	}
}

func (s *Server) startAdminSession(w http.ResponseWriter, username string) {
	token, h := randomToken()
	s.mu.Lock()
	s.admins[h] = adminSession{username: username, expires: s.now().Add(AdminLifetime)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(AdminLifetime.Seconds())})
}

type stateOrg struct {
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	Server     string `json:"server"`
	Key        string `json:"key"`
	Record     string `json:"record"`
	RecordName string `json:"recordName"`
	DNSChecked int64  `json:"dnsChecked"`
}

func (s *Server) adminState(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	out := map[string]any{"setup": !s.st.HasAdmin()}
	if user, ok := s.adminSession(r); ok {
		out["admin"] = user
		out["recoveryLeft"] = s.st.RecoveryLeft(user)
		if o, _, ok := s.org(); ok {
			out["org"] = stateOrg{Name: o.Name, Domain: o.Domain, Server: o.Server, Key: proto.B64(o.Pub),
				Record: proto.TXTValue(o.Server, o.Key()), RecordName: "_mohur." + o.Domain, DNSChecked: o.DNSChecked}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func qrRows(text string) []string {
	code, err := qrcode.Encode([]byte(text))
	if err != nil {
		return nil
	}
	rows := make([]string, len(code))
	for y, line := range code {
		b := make([]byte, len(line))
		for x, dark := range line {
			b[x] = '0'
			if dark {
				b[x] = '1'
			}
		}
		rows[y] = string(b)
	}
	return rows
}

func (s *Server) setupStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !sameOrigin(r) || !s.allow(r, "setup", 10) || readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	code := store.NormalizeCode(in.Code)
	if s.st.HasAdmin() || !s.st.CheckSetupCode(code) {
		fail(w, http.StatusForbidden, "That setup code is not right. The server prints it when it starts for the first time.")
		return
	}
	seed := store.NewSeed()
	s.mu.Lock()
	s.setupSeed[sha256.Sum256([]byte(code))] = seed
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"seed": seed, "qr": qrRows(store.SeedURI("setup", "admin", seed))})
}

func (s *Server) setupFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code     string `json:"code"`
		OrgName  string `json:"orgName"`
		Domain   string `json:"domain"`
		Server   string `json:"server"`
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !sameOrigin(r) || !s.allow(r, "setup", 10) || readJSON(r, 8<<10, &in) != nil {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	code := store.NormalizeCode(in.Code)
	name, ok := proto.DisplayName(in.OrgName)
	if !ok {
		fail(w, http.StatusBadRequest, "Enter the organization's name.")
		return
	}
	domain, err := proto.Domain(in.Domain)
	if err != nil {
		fail(w, http.StatusBadRequest, "Enter the organization's domain, such as example.com.")
		return
	}
	server, err := proto.ServerName(strings.ToLower(strings.TrimSpace(in.Server)), domain)
	if err != nil {
		fail(w, http.StatusBadRequest, "The server address must be the domain or a name under it, such as mohur."+domain+".")
		return
	}
	user := strings.ToLower(strings.TrimSpace(in.Username))
	if !proto.Username(user) {
		fail(w, http.StatusBadRequest, "Use lowercase letters and digits for the admin name.")
		return
	}
	if !store.PasswordOK(in.Password) {
		fail(w, http.StatusBadRequest, "Use a password of at least 15 characters.")
		return
	}
	h := sha256.Sum256([]byte(code))
	s.mu.Lock()
	seed := s.setupSeed[h]
	s.mu.Unlock()
	if seed == "" {
		fail(w, http.StatusForbidden, "Start again with the setup code.")
		return
	}
	codes, err := s.st.FinishSetup(store.Setup{Code: code, OrgName: name, Domain: domain, Server: server, Username: user, Password: in.Password, Seed: seed, TOTP: strings.TrimSpace(in.TOTP)})
	if err != nil {
		fail(w, http.StatusForbidden, "The authenticator code was not accepted. Wait for a new code and try again.")
		return
	}
	s.mu.Lock()
	delete(s.setupSeed, h)
	s.mu.Unlock()
	s.log.Info("setup finished", "domain", domain, "admin", user)
	s.startAdminSession(w, user)
	writeJSON(w, http.StatusOK, map[string]any{"recovery": codes})
}

func (s *Server) signIn(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !sameOrigin(r) || !s.allow(r, "signin", 20) || readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusForbidden, "Refused. Wait a minute and try again.")
		return
	}
	user := strings.ToLower(strings.TrimSpace(in.Username))
	if s.st.SignIn(user, in.Password, strings.TrimSpace(in.Code)) != nil {
		fail(w, http.StatusUnauthorized, "The name, password or code was not accepted.")
		return
	}
	s.startAdminSession(w, user)
	writeJSON(w, http.StatusOK, map[string]any{"admin": user})
}

func (s *Server) signOut(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	if c, err := r.Cookie(adminCookie); err == nil {
		h := sha256.Sum256([]byte(c.Value))
		s.mu.Lock()
		delete(s.admins, h)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{})
}

const badResetCode = "That reset code is not right or has expired. Run sudo mohurd reset-admin on the server for a new one."

// resetSlot keys the new authenticator seed of a reset in progress, apart
// from setup's.
func resetSlot(code string) [32]byte { return sha256.Sum256([]byte("reset/" + code)) }

// resetStart checks a code from `mohurd reset-admin` and offers a new
// authenticator for the admin, whose name it shows.
func (s *Server) resetStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !sameOrigin(r) || !s.allow(r, "reset", 10) || readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusForbidden, "Refused. Wait a minute and try again.")
		return
	}
	code := store.NormalizeCode(in.Code)
	admin := s.st.AdminName()
	if admin == "" || !s.st.CheckResetCode(code) {
		fail(w, http.StatusForbidden, badResetCode)
		return
	}
	label := "Mohur"
	if o, _, ok := s.org(); ok {
		label = o.Name
	}
	seed := store.NewSeed()
	s.mu.Lock()
	s.setupSeed[resetSlot(code)] = seed
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"admin": admin, "seed": seed, "qr": qrRows(store.SeedURI(label, admin, seed))})
}

// resetFinish sets the new password and authenticator, ends the admin's
// other sessions and signs this browser in.
func (s *Server) resetFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code     string `json:"code"`
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !sameOrigin(r) || !s.allow(r, "reset", 10) || readJSON(r, 8<<10, &in) != nil {
		fail(w, http.StatusForbidden, "Refused. Wait a minute and try again.")
		return
	}
	code := store.NormalizeCode(in.Code)
	if !store.PasswordOK(in.Password) {
		fail(w, http.StatusBadRequest, "Use a password of at least 15 characters.")
		return
	}
	slot := resetSlot(code)
	s.mu.Lock()
	seed := s.setupSeed[slot]
	s.mu.Unlock()
	if seed == "" {
		fail(w, http.StatusForbidden, "Start again with the reset code.")
		return
	}
	user := strings.ToLower(strings.TrimSpace(in.Username))
	codes, err := s.st.ResetAdmin(store.Reset{Code: code, Username: user, Password: in.Password, Seed: seed, TOTP: strings.TrimSpace(in.TOTP)})
	switch {
	case errors.Is(err, store.ErrRefused):
		fail(w, http.StatusForbidden, "The authenticator code was not accepted. Wait for a new code and try again.")
		return
	case err != nil:
		fail(w, http.StatusForbidden, badResetCode)
		return
	}
	s.mu.Lock()
	delete(s.setupSeed, slot)
	for h, a := range s.admins {
		if a.username == user {
			delete(s.admins, h)
		}
	}
	s.mu.Unlock()
	s.log.Info("admin access reset", "admin", user)
	s.startAdminSession(w, user)
	writeJSON(w, http.StatusOK, map[string]any{"admin": user, "recovery": codes})
}

// domainCheck looks at this organization from outside, as a partner would.
func (s *Server) domainCheck(w http.ResponseWriter, r *http.Request, _ string) {
	o, _, ok := s.org()
	if !ok {
		fail(w, http.StatusConflict, "Finish setup first.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	t, err := s.disc.TXT(ctx, o.Domain)
	if err != nil {
		_ = s.st.MarkDNS(0)
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "problem": "No Mohur record was found at _mohur." + o.Domain + ". DNS changes can take a few minutes to appear."})
		return
	}
	if t.Server != o.Server || !t.Key.Equal(o.Key()) {
		_ = s.st.MarkDNS(0)
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "problem": "The record exists but does not match this server. Replace it with the record shown here."})
		return
	}
	if _, err := s.disc.Lookup(ctx, o.Domain); err != nil {
		_ = s.st.MarkDNS(0)
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "problem": "The record is right, but https://" + o.Server + " could not be reached with a valid certificate."})
		return
	}
	now := s.now().Unix()
	_ = s.st.MarkDNS(now)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checked": now})
}

type personView struct {
	Username      string `json:"username"`
	Address       string `json:"address"`
	Name          string `json:"name"`
	State         string `json:"state"`
	InviteExpires int64  `json:"inviteExpires,omitempty"`
	Device        string `json:"device,omitempty"`
	Joined        int64  `json:"joined,omitempty"`
	// Partners names the connected partners this person may write with.
	Partners []string `json:"partners"`
}

func (s *Server) peopleList(w http.ResponseWriter, _ *http.Request, _ string) {
	o, _, _ := s.org()
	people, err := s.st.People()
	if err != nil {
		fail(w, http.StatusInternalServerError, "The list could not be read.")
		return
	}
	conns, _ := s.st.Connections()
	sort.Slice(conns, func(i, j int) bool { return conns[i].Name < conns[j].Name })
	out := make([]personView, 0, len(people))
	for _, p := range people {
		v := personView{Username: p.Username, Address: p.Username + "@" + o.Domain, Name: p.Name, State: p.State, InviteExpires: p.InviteExpires, Partners: []string{}}
		if p.Device != nil {
			v.Device, v.Joined = p.Device.Label, p.Device.Joined
		}
		for _, c := range conns {
			if c.State == store.Connected && c.Allows(p.Username) {
				v.Partners = append(v.Partners, c.Name)
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) inviteText(code string) string {
	o, _, _ := s.org()
	var groups []string
	for i := 0; i < len(code); i += 4 {
		groups = append(groups, code[i:min(i+4, len(code))])
	}
	return o.Domain + "/" + strings.Join(groups, "-")
}

func (s *Server) peopleInvite(w http.ResponseWriter, r *http.Request, admin string) {
	var in struct {
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	user := strings.ToLower(strings.TrimSpace(in.Username))
	name, ok := proto.DisplayName(in.Name)
	if !proto.Username(user) || !ok {
		fail(w, http.StatusBadRequest, "Enter a name and a short user name of lowercase letters and digits.")
		return
	}
	code, p, err := s.st.Invite(user, name)
	if errors.Is(err, store.ErrRefused) {
		fail(w, http.StatusConflict, "This person already uses Mohur. To move them to a new computer, choose New device.")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "The invite could not be made.")
		return
	}
	s.log.Info("invite made", "admin", admin, "person", user)
	writeJSON(w, http.StatusOK, map[string]any{"invite": s.inviteText(code), "expires": p.InviteExpires})
}

func (s *Server) peopleRemove(w http.ResponseWriter, r *http.Request, admin string) {
	var in struct {
		Username string `json:"username"`
	}
	if readJSON(r, 4<<10, &in) != nil || s.st.Remove(in.Username) != nil {
		fail(w, http.StatusBadRequest, "That person could not be removed.")
		return
	}
	s.changed()
	s.tellPartners("")
	s.log.Info("person removed", "admin", admin, "person", in.Username)
	writeJSON(w, http.StatusOK, map[string]any{})
}

// peopleReset removes a person's device and makes a new invite, for a lost or
// replaced computer. Their partners see a new-device notice afterwards.
func (s *Server) peopleReset(w http.ResponseWriter, r *http.Request, admin string) {
	var in struct {
		Username string `json:"username"`
	}
	if readJSON(r, 4<<10, &in) != nil || s.st.ResetDevice(in.Username) != nil {
		fail(w, http.StatusBadRequest, "That device could not be reset.")
		return
	}
	p, err := s.st.Person(in.Username)
	if err != nil {
		fail(w, http.StatusInternalServerError, "The invite could not be made.")
		return
	}
	s.changed()
	s.tellPartners("")
	code, p, err := s.st.Invite(p.Username, p.Name)
	if err != nil {
		fail(w, http.StatusInternalServerError, "The invite could not be made.")
		return
	}
	s.log.Info("device reset", "admin", admin, "person", in.Username)
	writeJSON(w, http.StatusOK, map[string]any{"invite": s.inviteText(code), "expires": p.InviteExpires})
}

type partnerView struct {
	Domain       string `json:"domain"`
	Name         string `json:"name"`
	Server       string `json:"server"`
	State        string `json:"state"`
	Created      int64  `json:"created"`
	Updated      int64  `json:"updated"`
	SecurityCode string `json:"securityCode,omitempty"`
	NewKey       string `json:"newKey,omitempty"`
	NewName      string `json:"newName,omitempty"`
	NewCode      string `json:"newCode,omitempty"`
	// Chosen and People say who here may write with the partner; Theirs is
	// how many of the partner's people our people see.
	Chosen bool     `json:"chosen"`
	People []string `json:"people"`
	Theirs *int     `json:"theirs,omitempty"`
}

func (s *Server) partnersList(w http.ResponseWriter, r *http.Request, _ string) {
	o, _, _ := s.org()
	conns, err := s.st.Connections()
	if err != nil {
		fail(w, http.StatusInternalServerError, "The list could not be read.")
		return
	}
	sort.Slice(conns, func(i, j int) bool { return conns[i].Domain < conns[j].Domain })
	// Count each connected partner's people at once; one that cannot be
	// reached shows its last known count.
	theirs := make([]*int, len(conns))
	var wg sync.WaitGroup
	for i, c := range conns {
		if c.State != store.Connected {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			n := len(s.partnerPeople(ctx, c, false))
			theirs[i] = &n
		}()
	}
	wg.Wait()
	out := make([]partnerView, 0, len(conns))
	for i, c := range conns {
		v := partnerView{Domain: c.Domain, Name: c.Name, Server: c.Server, State: c.State, Created: c.Created, Updated: c.Updated,
			Chosen: c.Chosen, People: append([]string{}, c.People...), Theirs: theirs[i]}
		if k, err := proto.PublicKey(c.Key); err == nil {
			v.SecurityCode = proto.Fingerprint(o.Key(), k)
		}
		if c.NewKey != "" {
			v.NewKey, v.NewName = c.NewKey, c.NewName
			if k, err := proto.PublicKey(c.NewKey); err == nil {
				v.NewCode = proto.Fingerprint(o.Key(), k)
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func discoverMessage(err error) string {
	switch {
	case errors.Is(err, discover.ErrNoRecord):
		return "That domain has no Mohur DNS record yet. Its admin adds it on their Domain page."
	case errors.Is(err, discover.ErrMismatch):
		return "That domain's DNS record and its server do not agree, so it cannot be trusted. Ask its admin to check their Domain page."
	default:
		return "That organization's Mohur server could not be reached with a valid certificate."
	}
}

func (s *Server) partnerDomain(w http.ResponseWriter, r *http.Request) (string, bool) {
	var in struct {
		Domain string `json:"domain"`
	}
	if readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return "", false
	}
	d, err := proto.Domain(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(in.Domain), "https://"), "http://"))
	o, _, _ := s.org()
	if err != nil || d == o.Domain {
		fail(w, http.StatusBadRequest, "Enter the other organization's domain, such as partner.com.")
		return "", false
	}
	return d, true
}

func (s *Server) partnersPreview(w http.ResponseWriter, r *http.Request, _ string) {
	d, ok := s.partnerDomain(w, r)
	if !ok {
		return
	}
	doc, err := s.disc.Lookup(r.Context(), d)
	if err != nil {
		fail(w, http.StatusBadGateway, discoverMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": doc.Domain, "name": doc.Name, "server": doc.Server})
}

func (s *Server) partnersConnect(w http.ResponseWriter, r *http.Request, admin string) {
	d, ok := s.partnerDomain(w, r)
	if !ok {
		return
	}
	doc, err := s.disc.Lookup(r.Context(), d)
	if err != nil {
		fail(w, http.StatusBadGateway, discoverMessage(err))
		return
	}
	c, err := s.st.Ask(doc)
	if err != nil {
		fail(w, http.StatusConflict, "There is already a connection with this organization.")
		return
	}
	if err := s.fedCall(r.Context(), c, "POST", "/fed/v1/connect", struct{}{}, nil); err != nil {
		s.log.Warn("connect request not delivered", "partner", d, "err", err)
		fail(w, http.StatusBadGateway, "The request was saved but "+d+" did not receive it. Try Connect again later.")
		return
	}
	if c.State == store.Connected {
		_ = s.fedCall(r.Context(), c, "POST", "/fed/v1/accept", struct{}{}, nil)
		s.changed()
	}
	s.log.Info("connection requested", "admin", admin, "partner", d, "state", c.State)
	writeJSON(w, http.StatusOK, map[string]any{"state": c.State})
}

func (s *Server) partnersAccept(w http.ResponseWriter, r *http.Request, admin string) {
	d, ok := s.partnerDomain(w, r)
	if !ok {
		return
	}
	// Verify the organization again now: accept only the key it still shows.
	if c, err := s.st.Connection(d); err == nil && c.State == store.Incoming {
		doc, err := s.disc.Lookup(r.Context(), d)
		if err != nil {
			fail(w, http.StatusBadGateway, discoverMessage(err))
			return
		}
		if doc.Key != c.Key {
			fail(w, http.StatusConflict, d+" changed its key after asking. Decline this request; they can ask again.")
			return
		}
	}
	c, err := s.st.Accept(d)
	if err != nil {
		fail(w, http.StatusConflict, "There is no request from this organization to accept.")
		return
	}
	if err := s.fedCall(r.Context(), c, "POST", "/fed/v1/accept", struct{}{}, nil); err != nil {
		s.log.Warn("acceptance not delivered", "partner", d, "err", err)
	}
	s.changed()
	s.log.Info("connection accepted", "admin", admin, "partner", d)
	writeJSON(w, http.StatusOK, map[string]any{"state": c.State})
}

func (s *Server) partnersRemove(w http.ResponseWriter, r *http.Request, admin string) {
	d, ok := s.partnerDomain(w, r)
	if !ok {
		return
	}
	c, err := s.st.Connection(d)
	if err != nil {
		fail(w, http.StatusNotFound, "There is no connection with this organization.")
		return
	}
	if c.State == store.Connected || c.State == store.Outgoing {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		_ = s.fedCall(ctx, c, "POST", "/fed/v1/disconnect", struct{}{}, nil)
		cancel()
	}
	if err := s.st.Disconnect(d); err != nil {
		fail(w, http.StatusInternalServerError, "The connection could not be removed.")
		return
	}
	s.changed()
	s.log.Info("connection removed", "admin", admin, "partner", d)
	writeJSON(w, http.StatusOK, map[string]any{})
}

// partnersTrust accepts a partner's new key, after verifying it again now.
func (s *Server) partnersTrust(w http.ResponseWriter, r *http.Request, admin string) {
	var in struct {
		Domain string `json:"domain"`
		Key    string `json:"key"`
	}
	if readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	doc, err := s.disc.Lookup(r.Context(), in.Domain)
	if err != nil {
		fail(w, http.StatusBadGateway, discoverMessage(err))
		return
	}
	if doc.Key != in.Key {
		fail(w, http.StatusConflict, "The organization's key changed again. Reload the page and review it.")
		return
	}
	if _, err := s.st.TrustNewKey(in.Domain, in.Key); err != nil {
		fail(w, http.StatusConflict, "There is no key change to accept.")
		return
	}
	s.changed()
	s.log.Info("partner key accepted", "admin", admin, "partner", in.Domain)
	writeJSON(w, http.StatusOK, map[string]any{})
}

// partnersAccess sets who here may write with a partner: everyone, or only
// the chosen people. The partner then sees only them, and our server refuses
// anything to or from anyone else here.
func (s *Server) partnersAccess(w http.ResponseWriter, r *http.Request, admin string) {
	var in struct {
		Domain string   `json:"domain"`
		Chosen bool     `json:"chosen"`
		People []string `json:"people"`
	}
	if readJSON(r, 256<<10, &in) != nil || len(in.People) > store.MaxChosen {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	d, err := proto.Domain(in.Domain)
	if err != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	for _, u := range in.People {
		if !proto.Username(u) {
			fail(w, http.StatusBadRequest, "Choose people from your organization.")
			return
		}
	}
	c, err := s.st.SetAccess(d, in.Chosen, in.People)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "There is no connection with this organization.")
		return
	}
	if err != nil {
		fail(w, http.StatusBadRequest, "Choose people from your organization.")
		return
	}
	s.changed()
	s.tellPartners(c.Domain)
	s.log.Info("partner access changed", "admin", admin, "partner", c.Domain, "chosen", c.Chosen, "people", len(c.People))
	writeJSON(w, http.StatusOK, map[string]any{"chosen": c.Chosen, "people": append([]string{}, c.People...)})
}
