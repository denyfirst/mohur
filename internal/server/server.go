// Package server is mohurd's HTTPS surface: the admin pages and their API,
// the desktop app's API and the federation API other Mohur servers call.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/denyfirst/mohur/internal/discover"
	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
	"github.com/denyfirst/mohur/internal/updates"
	"github.com/denyfirst/mohur/web"
)

// Server serves one organization.
type Server struct {
	st      *store.Store
	disc    *discover.Verifier
	log     *slog.Logger
	clock   atomic.Pointer[func() time.Time]
	updates *updates.Service

	mu        sync.Mutex
	admins    map[[32]byte]adminSession
	clients   map[[32]byte]clientSession
	setupSeed map[[32]byte]string // setup code hash -> seed offered
	waiters   map[string][]chan struct{}
	limits    map[string]*window
	nonces    map[string]clientNonce
	// directory changes whenever who can write to whom may have changed:
	// people, partners or a partner's people. Apps read it with their mail.
	directory int64
}

type adminSession struct {
	username string
	expires  time.Time
}

type clientSession struct {
	user    string
	device  uint32
	expires time.Time
}

type clientNonce struct {
	user    string
	device  uint32
	expires time.Time
}

type window struct {
	start time.Time
	n     int
}

// New makes a server over an open store.
func New(st *store.Store, disc *discover.Verifier, log *slog.Logger) *Server {
	s := &Server{st: st, disc: disc, log: log,
		admins: map[[32]byte]adminSession{}, clients: map[[32]byte]clientSession{},
		setupSeed: map[[32]byte]string{}, waiters: map[string][]chan struct{}{},
		limits: map[string]*window{}, nonces: map[string]clientNonce{}, directory: time.Now().Unix()}
	s.SetClock(time.Now)
	return s
}

// SetClock replaces the clock; tests only. It is safe while requests run.
func (s *Server) SetClock(now func() time.Time) { s.clock.Store(&now) }

func (s *Server) now() time.Time { return (*s.clock.Load())() }

// Handler returns the complete HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/mohur", s.wellKnown)

	// Admin pages: one document; the script shows the right view.
	mux.HandleFunc("GET /{$}", s.page)
	for _, p := range []string{"/people", "/partners", "/reports", "/domain", "/server", "/signin", "/setup", "/reset"} {
		mux.HandleFunc("GET "+p, s.page)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", web.Assets()))

	mux.HandleFunc("GET /admin/api/state", s.adminState)
	mux.HandleFunc("POST /admin/api/setup/start", s.setupStart)
	mux.HandleFunc("POST /admin/api/setup/finish", s.setupFinish)
	mux.HandleFunc("POST /admin/api/signin", s.signIn)
	mux.HandleFunc("POST /admin/api/signout", s.signOut)
	mux.HandleFunc("POST /admin/api/reset/start", s.resetStart)
	mux.HandleFunc("POST /admin/api/reset/finish", s.resetFinish)
	mux.HandleFunc("POST /admin/api/domain/check", s.admin(s.domainCheck))
	mux.HandleFunc("GET /admin/api/people", s.admin(s.peopleList))
	mux.HandleFunc("POST /admin/api/people/invite", s.admin(s.peopleInvite))
	mux.HandleFunc("POST /admin/api/people/remove", s.admin(s.peopleRemove))
	mux.HandleFunc("POST /admin/api/people/reset", s.admin(s.peopleReset))
	mux.HandleFunc("POST /admin/api/people/partners", s.admin(s.peoplePartners))
	mux.HandleFunc("GET /admin/api/partners", s.admin(s.partnersList))
	mux.HandleFunc("GET /admin/api/partners/choices", s.admin(s.partnerChoices))
	mux.HandleFunc("POST /admin/api/partners/preview", s.admin(s.partnersPreview))
	mux.HandleFunc("POST /admin/api/partners/connect", s.admin(s.partnersConnect))
	mux.HandleFunc("POST /admin/api/partners/accept", s.admin(s.partnersAccept))
	mux.HandleFunc("POST /admin/api/partners/remove", s.admin(s.partnersRemove))
	mux.HandleFunc("POST /admin/api/partners/trust", s.admin(s.partnersTrust))
	mux.HandleFunc("POST /admin/api/partners/access", s.admin(s.partnersAccess))
	mux.HandleFunc("GET /admin/api/reports", s.admin(s.reportsList))
	mux.HandleFunc("POST /admin/api/reports/close", s.admin(s.reportsClose))
	mux.HandleFunc("GET /admin/api/updates", s.admin(s.updatesState))
	mux.HandleFunc("POST /admin/api/updates/check", s.admin(s.updatesCheck))
	mux.HandleFunc("POST /admin/api/updates/daily", s.admin(s.updatesDaily))

	mux.HandleFunc("POST /api/v1/join", s.join)
	mux.HandleFunc("POST /api/v1/session/challenge", s.sessionChallenge)
	mux.HandleFunc("POST /api/v1/session", s.sessionCreate)
	mux.HandleFunc("GET /api/v1/contacts", s.client(s.contacts))
	mux.HandleFunc("GET /api/v1/keys", s.client(s.keys))
	mux.HandleFunc("GET /api/v1/prekeys", s.client(s.prekeyCount))
	mux.HandleFunc("POST /api/v1/prekeys", s.client(s.prekeys))
	mux.HandleFunc("POST /api/v1/send", s.client(s.send))
	mux.HandleFunc("GET /api/v1/inbox", s.client(s.inbox))
	mux.HandleFunc("POST /api/v1/inbox/ack", s.client(s.ack))
	mux.HandleFunc("POST /api/v1/blobs", s.client(s.blobUpload))
	mux.HandleFunc("GET /api/v1/blobs/{id}", s.client(s.blobDownload))
	mux.HandleFunc("POST /api/v1/report", s.client(s.report))

	mux.HandleFunc("POST /fed/v1/connect", s.fedConnect)
	mux.HandleFunc("POST /fed/v1/accept", s.fed(s.fedAccept))
	mux.HandleFunc("POST /fed/v1/disconnect", s.fed(s.fedDisconnect))
	mux.HandleFunc("GET /fed/v1/directory", s.fed(s.fedDirectory))
	mux.HandleFunc("GET /fed/v1/keys", s.fed(s.fedKeys))
	mux.HandleFunc("POST /fed/v1/deliver", s.fed(s.fedDeliver))
	mux.HandleFunc("POST /fed/v1/changed", s.fed(s.fedChanged))
	mux.HandleFunc("PUT /fed/v1/blobs/{id}", s.fedBlob)

	return secureHeaders(mux)
}

func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Strict-Transport-Security", "max-age=63072000")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Cross-Origin-Resource-Policy", "same-origin")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// Run starts background work: sweeping old data and re-checking partners.
func (s *Server) Run(ctx context.Context) {
	sweep := time.NewTicker(10 * time.Minute)
	recheck := time.NewTicker(6 * time.Hour)
	defer sweep.Stop()
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			if err := s.st.Sweep(); err != nil {
				s.log.Warn("sweep failed", "err", err)
			}
			s.expireSessions()
		case <-recheck.C:
			s.recheckPartners(ctx)
		}
	}
}

func (s *Server) expireSessions() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.admins {
		if now.After(v.expires) {
			delete(s.admins, k)
		}
	}
	for k, v := range s.clients {
		if now.After(v.expires) {
			delete(s.clients, k)
		}
	}
	for k, v := range s.nonces {
		if now.After(v.expires) {
			delete(s.nonces, k)
		}
	}
	for k, v := range s.limits {
		if now.Sub(v.start) > time.Minute {
			delete(s.limits, k)
		}
	}
}

// recheckPartners verifies every partner again. A partner whose verified key
// changed is paused until an admin accepts the new key; one that cannot be
// reached is left as it is.
func (s *Server) recheckPartners(ctx context.Context) {
	conns, err := s.st.Connections()
	if err != nil {
		return
	}
	for _, c := range conns {
		if c.State != store.Connected {
			continue
		}
		d, err := s.disc.Lookup(ctx, c.Domain)
		if err != nil {
			continue
		}
		if d.Key != c.Key {
			_ = s.st.KeyMismatch(d)
			s.changed()
			s.log.Warn("partner key changed; connection paused", "partner", c.Domain)
			continue
		}
		_ = s.st.Checked(d)
	}
}

// allow is a small per-source limit for unauthenticated requests.
func (s *Server) allow(r *http.Request, bucket string, perMinute int) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	key := bucket + "|" + host
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.limits[key]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		s.limits[key] = w
	}
	w.n++
	return w.n <= perMinute
}

func (s *Server) org() (store.Org, ed25519.PrivateKey, bool) {
	o, k, err := s.st.Org()
	return o, k, err == nil
}

func (s *Server) wellKnown(w http.ResponseWriter, _ *http.Request) {
	o, k, ok := s.org()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	d := proto.OrgDoc{Domain: o.Domain, Name: o.Name, Server: o.Server, Key: proto.B64(o.Pub)}
	proto.SignOrg(&d, k)
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(web.Page())
}

// Waiters let a long-polling inbox request return as soon as mail arrives.
func (s *Server) wait(user string) (chan struct{}, func()) {
	ch := make(chan struct{})
	s.mu.Lock()
	s.waiters[user] = append(s.waiters[user], ch)
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		list := s.waiters[user]
		for i, c := range list {
			if c == ch {
				s.waiters[user] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(s.waiters[user]) == 0 {
			delete(s.waiters, user)
		}
	}
}

func (s *Server) notify(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.waiters[user] {
		close(ch)
	}
	delete(s.waiters, user)
}

// changed records that who can write to whom may have changed and wakes every
// waiting app, so each reads its contacts at once instead of within a minute.
func (s *Server) changed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.directory++
	for user, list := range s.waiters {
		for _, ch := range list {
			close(ch)
		}
		delete(s.waiters, user)
	}
}

func (s *Server) directoryVersion() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.directory
}

// tellPartners lets connected partners (or only the one named) know that
// our people changed, so their apps show it at once. It is best effort:
// partners read our directory again within a minute anyway.
func (s *Server) tellPartners(only string) {
	conns, err := s.st.Connections()
	if err != nil {
		return
	}
	for _, c := range conns {
		if c.State != store.Connected || (only != "" && c.Domain != only) {
			continue
		}
		go func(c store.Connection) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.fedCall(ctx, c, "POST", "/fed/v1/changed", struct{}{}, nil); err != nil {
				s.log.Debug("partner not told of a change", "partner", c.Domain, "err", err)
			}
		}(c)
	}
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("mohur: random source failed")
	}
	return proto.B64(b)
}

func randomToken() (string, [32]byte) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("mohur: random source failed")
	}
	t := proto.B64(b)
	return t, sha256.Sum256([]byte(t))
}

// Problem is the JSON error body. Message is safe to show to a person.
type Problem struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Problem{Error: msg})
}

// readJSON decodes a bounded JSON body that must contain exactly one value of
// a known shape.
func readJSON(r *http.Request, limit int64, v any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return errors.New("content type")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
