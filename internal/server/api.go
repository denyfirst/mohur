package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
)

// ClientLifetime is how long an app session token lasts. The app signs in
// again with its device key on its own; people never see this.
const ClientLifetime = time.Hour

func (s *Server) client(h func(http.ResponseWriter, *http.Request, clientSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || token == "" {
			fail(w, http.StatusUnauthorized, "Sign in again.")
			return
		}
		h2 := sha256.Sum256([]byte(token))
		s.mu.Lock()
		c, found := s.clients[h2]
		s.mu.Unlock()
		if !found || s.now().After(c.expires) {
			fail(w, http.StatusUnauthorized, "Sign in again.")
			return
		}
		// A removed or reset person loses access at once, not at token expiry.
		p, err := s.st.Person(c.user)
		if err != nil || p.State != store.Active || p.Device == nil || p.Device.ID != c.device {
			fail(w, http.StatusUnauthorized, "This device is no longer part of the organization.")
			return
		}
		h(w, r, c)
	}
}

type joinRequest struct {
	Invite         string         `json:"invite"`
	Label          string         `json:"label"`
	IdentityKey    string         `json:"identityKey"`
	AuthKey        string         `json:"authKey"`
	RegistrationID uint32         `json:"registrationId"`
	SignedPreKey   proto.PreKey   `json:"signedPreKey"`
	KyberPreKey    proto.PreKey   `json:"kyberPreKey"`
	PreKeys        []proto.PreKey `json:"preKeys"`
}

func checkPreKey(k proto.PreKey, signed bool, maxLen int) bool {
	pub, err := proto.UnB64(k.Pub)
	if err != nil || len(pub) < 33 || len(pub) > maxLen || k.ID == 0 || k.ID > 1<<24 {
		return false
	}
	if signed {
		sig, err := proto.UnB64(k.Sig)
		return err == nil && len(sig) == 64
	}
	return k.Sig == ""
}

// Kyber-1024 public keys are 1568 bytes plus libsignal's type byte.
const maxKyberPub = 1600

func checkKeys(identity, auth string, signed, kyber proto.PreKey, prekeys []proto.PreKey) bool {
	if _, err := proto.IdentityKeyBytes(identity); err != nil {
		return false
	}
	if _, err := proto.PublicKey(auth); err != nil {
		return false
	}
	if !checkPreKey(signed, true, 33) || !checkPreKey(kyber, true, maxKyberPub) || len(prekeys) > store.MaxPreKeys {
		return false
	}
	for _, k := range prekeys {
		if !checkPreKey(k, false, 33) {
			return false
		}
	}
	return true
}

func (s *Server) join(w http.ResponseWriter, r *http.Request) {
	var in joinRequest
	if !s.allow(r, "join", 10) || readJSON(r, 64<<10, &in) != nil {
		fail(w, http.StatusBadRequest, "Refused. Wait a minute and try again.")
		return
	}
	o, key, ok := s.org()
	if !ok {
		fail(w, http.StatusConflict, "This server is not set up yet.")
		return
	}
	domain, code, found := strings.Cut(strings.TrimSpace(in.Invite), "/")
	label, lok := proto.DisplayName(in.Label)
	if !found || domain != o.Domain || !lok || in.RegistrationID == 0 || in.RegistrationID > 16380 ||
		!checkKeys(in.IdentityKey, in.AuthKey, in.SignedPreKey, in.KyberPreKey, in.PreKeys) {
		fail(w, http.StatusBadRequest, "That invite is not for this organization.")
		return
	}
	p, err := s.st.Redeem(store.Join{Code: code, Label: label, IdentityKey: in.IdentityKey, AuthKey: in.AuthKey,
		RegistrationID: in.RegistrationID, SignedPreKey: in.SignedPreKey, KyberPreKey: in.KyberPreKey, PreKeys: in.PreKeys},
		func(c *proto.DeviceCert) { proto.SignDevice(c, key) })
	if err != nil {
		fail(w, http.StatusForbidden, "That invite has expired or was already used. Ask your admin for a new one.")
		return
	}
	s.changed()
	s.tellPartners("")
	s.log.Info("device joined", "person", p.Username, "device", p.Device.ID)
	writeJSON(w, http.StatusOK, map[string]any{"cert": p.Device.Cert})
}

func (s *Server) sessionChallenge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
		Device  uint32 `json:"device"`
	}
	if !s.allow(r, "session", 60) || readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	user, domain, err := proto.Address(in.Address)
	o, _, _ := s.org()
	if err != nil || domain != o.Domain {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	nonce := randomID()
	s.mu.Lock()
	s.nonces[nonce] = clientNonce{user: user, device: in.Device, expires: s.now().Add(time.Minute)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"nonce": nonce})
}

func (s *Server) sessionCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
		Device  uint32 `json:"device"`
		Nonce   string `json:"nonce"`
		Sig     string `json:"sig"`
	}
	if !s.allow(r, "session", 60) || readJSON(r, 4<<10, &in) != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	s.mu.Lock()
	n, ok := s.nonces[in.Nonce]
	delete(s.nonces, in.Nonce)
	s.mu.Unlock()
	user, domain, err := proto.Address(in.Address)
	if !ok || err != nil || n.user != user || n.device != in.Device || s.now().After(n.expires) {
		fail(w, http.StatusUnauthorized, "Refused.")
		return
	}
	p, err := s.st.Person(user)
	if err != nil || p.State != store.Active || p.Device == nil || p.Device.ID != in.Device {
		fail(w, http.StatusUnauthorized, "This device is no longer part of the organization.")
		return
	}
	auth, err := proto.PublicKey(p.Device.Cert.AuthKey)
	if err != nil || !proto.Verify(auth, in.Sig, proto.ContextSession, domain, in.Address, strconv.FormatUint(uint64(in.Device), 10), in.Nonce) {
		fail(w, http.StatusUnauthorized, "Refused.")
		return
	}
	token, h := randomToken()
	s.mu.Lock()
	s.clients[h] = clientSession{user: user, device: in.Device, expires: s.now().Add(ClientLifetime)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires": s.now().Add(ClientLifetime).Unix()})
}

type orgView struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Key    string `json:"key"`
}

// localPeople is this organization's directory: everyone with a device.
func (s *Server) localPeople() []proto.Person {
	return s.directoryWhere(func(string) bool { return true })
}

// localPeopleFor is the part of the directory a partner may see: the people
// here who may write with it.
func (s *Server) localPeopleFor(c store.Connection) []proto.Person {
	return s.directoryWhere(c.Allows)
}

func (s *Server) directoryWhere(include func(username string) bool) []proto.Person {
	people, _ := s.st.People()
	out := []proto.Person{}
	for _, p := range people {
		if p.State == store.Active && p.Device != nil && include(p.Username) {
			out = append(out, proto.Person{Address: p.Device.Cert.Address, Name: p.Name, Devices: []proto.DeviceCert{p.Device.Cert}})
		}
	}
	return out
}

// notAllowed is what a person hears when their admin has not chosen them to
// write with a partner.
func notAllowed(c store.Connection) string {
	return "You cannot write to " + c.Name + ". Your admin chooses who can, on the Partners page."
}

// partnerPeople returns a partner's directory, fetched again when older than
// a minute (or at once when fresh is set) and taken from cache when the
// partner cannot be reached.
func (s *Server) partnerPeople(ctx context.Context, c store.Connection, fresh bool) []proto.Person {
	cached, fetched, err := s.st.Directory(c.Domain)
	if err == nil && !fresh && s.now().Sub(fetched) < time.Minute {
		return cached
	}
	var got []proto.Person
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s.fedCall(ctx, c, "GET", "/fed/v1/directory", nil, &got) != nil {
		return cached
	}
	key, kerr := proto.PublicKey(c.Key)
	valid := []proto.Person{}
	for _, p := range got {
		if _, d, err := proto.Address(p.Address); err != nil || d != c.Domain || kerr != nil {
			continue
		}
		name, ok := proto.DisplayName(p.Name)
		if !ok || len(p.Devices) == 0 || len(p.Devices) > 8 {
			continue
		}
		good := true
		for _, d := range p.Devices {
			if d.Check(key, c.Domain) != nil || d.Address != p.Address {
				good = false
			}
		}
		if good {
			valid = append(valid, proto.Person{Address: p.Address, Name: name, Devices: p.Devices})
		}
		if len(valid) >= 10000 {
			break
		}
	}
	_ = s.st.SetDirectory(c.Domain, valid)
	return valid
}

// contacts lists colleagues and the people of each partner this person may
// write with. The directory version is read first, so a change made while
// the list is built shows as a newer version with the next mail.
func (s *Server) contacts(w http.ResponseWriter, r *http.Request, c clientSession) {
	version := s.directoryVersion()
	o, _, _ := s.org()
	people := s.localPeople()
	orgs := []orgView{{Domain: o.Domain, Name: o.Name, Key: proto.B64(o.Pub)}}
	conns, _ := s.st.Connections()
	for _, conn := range conns {
		if conn.State != store.Connected || !conn.Allows(c.user) {
			continue
		}
		orgs = append(orgs, orgView{Domain: conn.Domain, Name: conn.Name, Key: conn.Key})
		people = append(people, s.partnerPeople(r.Context(), conn, r.URL.Query().Get("fresh") == "1")...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"self": c.user + "@" + o.Domain, "orgs": orgs, "people": people, "directory": version})
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request, c clientSession) {
	user, domain, err := proto.Address(r.URL.Query().Get("address"))
	if err != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	o, _, _ := s.org()
	var bundles []proto.Bundle
	if domain == o.Domain {
		bundles, err = s.st.TakeBundle(user)
	} else {
		conn, cerr := s.st.Connection(domain)
		if cerr != nil || conn.State != store.Connected {
			fail(w, http.StatusForbidden, "Your organization is not connected with "+domain+".")
			return
		}
		if !conn.Allows(c.user) {
			fail(w, http.StatusForbidden, notAllowed(conn))
			return
		}
		err = s.fedCall(r.Context(), conn, "GET", "/fed/v1/keys?user="+user, nil, &bundles)
	}
	if err != nil || len(bundles) == 0 {
		fail(w, http.StatusNotFound, "That person has no device yet.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bundles": bundles})
}

func (s *Server) prekeys(w http.ResponseWriter, r *http.Request, c clientSession) {
	var in struct {
		PreKeys      []proto.PreKey `json:"preKeys"`
		SignedPreKey *proto.PreKey  `json:"signedPreKey,omitempty"`
		KyberPreKey  *proto.PreKey  `json:"kyberPreKey,omitempty"`
	}
	if readJSON(r, 64<<10, &in) != nil || len(in.PreKeys) > store.MaxPreKeys {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	for _, k := range in.PreKeys {
		if !checkPreKey(k, false, 33) {
			fail(w, http.StatusBadRequest, "Refused.")
			return
		}
	}
	if (in.SignedPreKey != nil && !checkPreKey(*in.SignedPreKey, true, 33)) || (in.KyberPreKey != nil && !checkPreKey(*in.KyberPreKey, true, maxKyberPub)) {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	n, err := s.st.AddPreKeys(c.user, c.device, in.PreKeys, in.SignedPreKey, in.KyberPreKey)
	if err != nil {
		fail(w, http.StatusConflict, "Refused.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

func (s *Server) send(w http.ResponseWriter, r *http.Request, c clientSession) {
	var in struct {
		Envelopes []proto.Envelope `json:"envelopes"`
	}
	if readJSON(r, 2*proto.MaxEnvelopesSend*proto.MaxBody, &in) != nil || len(in.Envelopes) == 0 || len(in.Envelopes) > proto.MaxEnvelopesSend {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	o, _, _ := s.org()
	me, err := s.st.Person(c.user)
	if err != nil || me.Device == nil {
		fail(w, http.StatusUnauthorized, "Sign in again.")
		return
	}
	from := c.user + "@" + o.Domain
	remote := map[string][]proto.Envelope{}
	var local []proto.Envelope
	ids := make([]string, len(in.Envelopes))
	for i, e := range in.Envelopes {
		if e.CheckShape() != nil {
			fail(w, http.StatusBadRequest, "Refused.")
			return
		}
		e.ID, e.From, e.FromDevice, e.FromCert, e.Time = randomID(), from, c.device, me.Device.Cert, s.now().Unix()
		for _, id := range e.Blobs {
			b, err := s.st.Blob(id)
			if err != nil || b.From != from || b.To != e.To {
				fail(w, http.StatusBadRequest, "An attached file is missing. Send it again.")
				return
			}
		}
		_, domain, _ := proto.Address(e.To)
		if domain == o.Domain {
			local = append(local, e)
		} else {
			remote[domain] = append(remote[domain], e)
		}
		ids[i] = e.ID
	}
	for domain, envs := range remote {
		conn, err := s.st.Connection(domain)
		if err != nil || conn.State != store.Connected {
			fail(w, http.StatusForbidden, "Your organization is not connected with "+domain+".")
			return
		}
		if !conn.Allows(c.user) {
			fail(w, http.StatusForbidden, notAllowed(conn))
			return
		}
		if err := s.forward(r.Context(), conn, envs); err != nil {
			s.log.Warn("delivery to partner failed", "partner", domain, "err", err)
			if unreachablePerson(err) {
				fail(w, http.StatusForbidden, "That person at "+conn.Name+" cannot receive messages from you. Their admin chooses who can.")
				return
			}
			fail(w, http.StatusBadGateway, domain+" could not be reached. Mohur will try again.")
			return
		}
	}
	for _, e := range local {
		if err := s.st.Enqueue(e); err != nil {
			fail(w, http.StatusConflict, "That person's device changed. Try again.")
			return
		}
		user, _, _ := proto.Address(e.To)
		s.notify(user)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ids": ids})
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request, c clientSession) {
	envs, err := s.st.Inbox(c.user, c.device, 100)
	if err != nil {
		fail(w, http.StatusInternalServerError, "Refused.")
		return
	}
	if len(envs) == 0 && r.URL.Query().Get("wait") == "1" {
		ch, done := s.wait(c.user)
		// Read again after registering, so mail that arrived in between is not missed.
		envs, err = s.st.Inbox(c.user, c.device, 100)
		if err == nil && len(envs) == 0 {
			select {
			case <-ch:
			case <-time.After(25 * time.Second):
			case <-r.Context().Done():
			}
			envs, err = s.st.Inbox(c.user, c.device, 100)
		}
		done()
		if err != nil {
			fail(w, http.StatusInternalServerError, "Refused.")
			return
		}
	}
	if envs == nil {
		envs = []proto.Envelope{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"envelopes": envs, "directory": s.directoryVersion()})
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request, c clientSession) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if readJSON(r, 64<<10, &in) != nil || len(in.IDs) > 500 {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	if err := s.st.Ack(c.user, in.IDs); err != nil {
		fail(w, http.StatusInternalServerError, "Refused.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// canReach reports whether the person here named from may send to address.
func (s *Server) canReach(from, address string) bool {
	user, domain, err := proto.Address(address)
	if err != nil {
		return false
	}
	o, _, _ := s.org()
	if domain == o.Domain {
		p, err := s.st.Person(user)
		return err == nil && p.State == store.Active
	}
	conn, err := s.st.Connection(domain)
	return err == nil && conn.State == store.Connected && conn.Allows(from)
}

func (s *Server) blobUpload(w http.ResponseWriter, r *http.Request, c clientSession) {
	o, _, _ := s.org()
	to := r.URL.Query().Get("to")
	if !s.canReach(c.user, to) || r.ContentLength > proto.MaxBlob {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, proto.MaxBlob)
	b, err := s.st.PutBlob(randomID(), c.user+"@"+o.Domain, to, r.Body)
	if err != nil {
		fail(w, http.StatusBadRequest, "The file could not be stored. Files can be up to 100 MB.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": b.ID})
}

func (s *Server) blobDownload(w http.ResponseWriter, r *http.Request, c clientSession) {
	o, _, _ := s.org()
	id := r.PathValue("id")
	b, err := s.st.Blob(id)
	if err != nil || b.To != c.user+"@"+o.Domain {
		fail(w, http.StatusNotFound, "That file is no longer available.")
		return
	}
	f, err := s.st.OpenBlob(id)
	if err != nil {
		fail(w, http.StatusNotFound, "That file is no longer available.")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(b.Size, 10))
	if _, err := io.Copy(w, f); err != nil && !errors.Is(err, context.Canceled) {
		s.log.Debug("file download ended early", "err", err)
	}
}

func (s *Server) prekeyCount(w http.ResponseWriter, _ *http.Request, c clientSession) {
	p, err := s.st.Person(c.user)
	if err != nil || p.Device == nil {
		fail(w, http.StatusUnauthorized, "Sign in again.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(p.Device.PreKeys)})
}
