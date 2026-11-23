package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/denyfirst/mohur/internal/proto"
	"github.com/denyfirst/mohur/internal/store"
)

// Federation requests carry these headers; the signature covers the method,
// path, both organizations, time, nonce and a hash of the body.
const (
	hFrom  = "Mohur-From"
	hTo    = "Mohur-To"
	hTime  = "Mohur-Time"
	hNonce = "Mohur-Nonce"
	hSig   = "Mohur-Signature"
)

const maxFedBody = 2 * proto.MaxEnvelopesSend * proto.MaxBody

func fedFields(method, path, from, to, at, nonce string, bodyHash []byte) []string {
	return []string{method, path, from, to, at, nonce, proto.B64(bodyHash)}
}

func (s *Server) signRequest(req *http.Request, to string, bodyHash []byte) error {
	o, key, ok := s.org()
	if !ok {
		return errors.New("not set up")
	}
	at := strconv.FormatInt(s.now().Unix(), 10)
	nonce := randomID()
	req.Header.Set(hFrom, o.Domain)
	req.Header.Set(hTo, to)
	req.Header.Set(hTime, at)
	req.Header.Set(hNonce, nonce)
	req.Header.Set(hSig, proto.Sign(key, proto.ContextFed, fedFields(req.Method, req.URL.RequestURI(), o.Domain, to, at, nonce, bodyHash)...))
	return nil
}

// fedCall sends a signed JSON request to a partner and decodes its answer.
func (s *Server) fedCall(ctx context.Context, c store.Connection, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	// The partner's server was verified by discovery: a name under its domain,
	// over HTTPS, and the dialer refuses private addresses unless the operator
	// allowed them. The path is always one of ours.
	req, err := http.NewRequestWithContext(ctx, method, "https://"+c.Server+path, bytes.NewReader(body)) // #nosec G704 -- verified partner server, see above
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	h := sha256.Sum256(body)
	if err := s.signRequest(req, c.Domain, h[:]); err != nil {
		return err
	}
	resp, err := s.disc.Client().Do(req) // #nosec G704 -- verified partner server
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var p Problem
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&p)
		return fmt.Errorf("%s answered %d: %s", c.Domain, resp.StatusCode, p.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// forward sends envelopes and their files to a partner. Files go first; each
// local copy is deleted once the envelopes that need it are delivered.
func (s *Server) forward(ctx context.Context, c store.Connection, envs []proto.Envelope) error {
	var sent []string
	for _, e := range envs {
		for _, id := range e.Blobs {
			if err := s.putBlob(ctx, c, id); err != nil {
				return err
			}
			sent = append(sent, id)
		}
	}
	if err := s.fedCall(ctx, c, "POST", "/fed/v1/deliver", map[string]any{"envelopes": envs}, nil); err != nil {
		return err
	}
	for _, id := range sent {
		_ = s.st.DeleteBlob(id)
	}
	return nil
}

func (s *Server) putBlob(ctx context.Context, c store.Connection, id string) error {
	b, err := s.st.Blob(id)
	if err != nil {
		return err
	}
	f, err := s.st.OpenBlob(id)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	defer f.Close()
	path := "/fed/v1/blobs/" + id + "?from=" + b.From + "&to=" + b.To
	req, err := http.NewRequestWithContext(ctx, "PUT", "https://"+c.Server+path, f)
	if err != nil {
		return err
	}
	req.ContentLength = b.Size
	req.Header.Set("Content-Type", "application/octet-stream")
	if err := s.signRequest(req, c.Domain, h.Sum(nil)); err != nil {
		return err
	}
	resp, err := s.disc.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s refused a file: %d", c.Domain, resp.StatusCode)
	}
	return nil
}

type fedRequest struct {
	from, path, at, nonce, sig string
}

// fedHeaders checks the parts of a federation request that need no key: it
// is addressed to us, it is recent, and its nonce is new.
func (s *Server) fedHeaders(r *http.Request) (fedRequest, bool) {
	o, _, ok := s.org()
	if !ok {
		return fedRequest{}, false
	}
	f := fedRequest{from: r.Header.Get(hFrom), path: r.URL.RequestURI(), at: r.Header.Get(hTime), nonce: r.Header.Get(hNonce), sig: r.Header.Get(hSig)}
	if d, err := proto.Domain(f.from); err != nil || d != f.from || f.from == o.Domain || r.Header.Get(hTo) != o.Domain || !proto.ID(f.nonce) {
		return fedRequest{}, false
	}
	at, err := strconv.ParseInt(f.at, 10, 64)
	if err != nil || s.now().Sub(time.Unix(at, 0)).Abs() > proto.FedClockSkew {
		return fedRequest{}, false
	}
	return f, true
}

func (s *Server) fedSigned(r *http.Request, f fedRequest, key ed25519.PublicKey, bodyHash []byte) bool {
	o, _, _ := s.org()
	return proto.Verify(key, f.sig, proto.ContextFed, fedFields(r.Method, f.path, f.from, o.Domain, f.at, f.nonce, bodyHash)...) && s.st.FreshNonce(f.nonce)
}

// fedConnect receives a connection request. The sender is not yet known, so
// it is verified from its domain the same way our admin verifies partners.
func (s *Server) fedConnect(w http.ResponseWriter, r *http.Request) {
	f, ok := s.fedHeaders(r)
	if !ok || !s.allow(r, "fed-connect", 30) {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	doc, err := s.disc.Lookup(r.Context(), f.from)
	if err != nil {
		fail(w, http.StatusForbidden, "Your organization could not be verified: "+discoverMessage(err))
		return
	}
	key, _ := proto.PublicKey(doc.Key)
	h := sha256.Sum256(body)
	if !s.fedSigned(r, f, key, h[:]) {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	c, err := s.st.Asked(doc)
	if err != nil {
		fail(w, http.StatusConflict, "Refused.")
		return
	}
	s.log.Info("connection request received", "partner", f.from, "state", c.State)
	writeJSON(w, http.StatusOK, map[string]any{"state": c.State})
}

// fed wraps handlers for partners we already know: the signature must verify
// with the pinned key, and the connection must be in a state the path allows.
func (s *Server) fed(h func(http.ResponseWriter, *http.Request, store.Connection, []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, ok := s.fedHeaders(r)
		if !ok {
			fail(w, http.StatusForbidden, "Refused.")
			return
		}
		c, err := s.st.Connection(f.from)
		if err != nil || !allowedState(r.URL.Path, c.State) {
			fail(w, http.StatusForbidden, "Refused.")
			return
		}
		key, err := proto.PublicKey(c.Key)
		if err != nil {
			fail(w, http.StatusForbidden, "Refused.")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxFedBody+1))
		if err != nil || len(body) > maxFedBody {
			fail(w, http.StatusRequestEntityTooLarge, "Refused.")
			return
		}
		hash := sha256.Sum256(body)
		if !s.fedSigned(r, f, key, hash[:]) {
			fail(w, http.StatusForbidden, "Refused.")
			return
		}
		h(w, r, c, body)
	}
}

func allowedState(path, state string) bool {
	switch path {
	case "/fed/v1/accept":
		return state == store.Outgoing || state == store.Connected
	case "/fed/v1/disconnect":
		return state != store.KeyChanged
	default:
		return state == store.Connected
	}
}

func (s *Server) fedAccept(w http.ResponseWriter, _ *http.Request, c store.Connection, _ []byte) {
	if _, err := s.st.Accepted(c.Domain); err != nil {
		fail(w, http.StatusConflict, "Refused.")
		return
	}
	s.log.Info("connection accepted by partner", "partner", c.Domain)
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) fedDisconnect(w http.ResponseWriter, _ *http.Request, c store.Connection, _ []byte) {
	_ = s.st.Disconnect(c.Domain)
	s.log.Info("connection removed by partner", "partner", c.Domain)
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) fedDirectory(w http.ResponseWriter, _ *http.Request, _ store.Connection, _ []byte) {
	writeJSON(w, http.StatusOK, s.localPeople())
}

func (s *Server) fedKeys(w http.ResponseWriter, r *http.Request, _ store.Connection, _ []byte) {
	user := r.URL.Query().Get("user")
	if !proto.Username(user) {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	b, err := s.st.TakeBundle(user)
	if err != nil {
		fail(w, http.StatusNotFound, "Refused.")
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) fedDeliver(w http.ResponseWriter, _ *http.Request, c store.Connection, body []byte) {
	var in struct {
		Envelopes []proto.Envelope `json:"envelopes"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || len(in.Envelopes) == 0 || len(in.Envelopes) > proto.MaxEnvelopesSend {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	o, _, _ := s.org()
	key, _ := proto.PublicKey(c.Key)
	for _, e := range in.Envelopes {
		_, fromDomain, ferr := proto.Address(e.From)
		_, toDomain, _ := proto.Address(e.To)
		if e.CheckShape() != nil || ferr != nil || fromDomain != c.Domain || toDomain != o.Domain || !proto.ID(e.ID) ||
			e.FromCert.Check(key, c.Domain) != nil || e.FromCert.Address != e.From || e.FromCert.Device != e.FromDevice {
			fail(w, http.StatusBadRequest, "Refused.")
			return
		}
		for _, id := range e.Blobs {
			b, err := s.st.Blob(id)
			if err != nil || b.From != e.From || b.To != e.To {
				fail(w, http.StatusBadRequest, "Refused.")
				return
			}
		}
	}
	for _, e := range in.Envelopes {
		e.Time = s.now().Unix()
		if err := s.st.Enqueue(e); err != nil {
			fail(w, http.StatusConflict, "Refused.")
			return
		}
		user, _, _ := proto.Address(e.To)
		s.notify(user)
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// fedBlob receives an encrypted file from a partner. The body is stored while
// it is hashed, and removed again if the signature does not cover that hash.
func (s *Server) fedBlob(w http.ResponseWriter, r *http.Request) {
	f, ok := s.fedHeaders(r)
	if !ok {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	c, err := s.st.Connection(f.from)
	key, kerr := proto.PublicKey(c.Key)
	o, _, _ := s.org()
	id, from, to := r.PathValue("id"), r.URL.Query().Get("from"), r.URL.Query().Get("to")
	_, fromDomain, ferr := proto.Address(from)
	toUser, toDomain, terr := proto.Address(to)
	if err != nil || kerr != nil || c.State != store.Connected || !proto.ID(id) || ferr != nil || terr != nil ||
		fromDomain != c.Domain || toDomain != o.Domain || r.ContentLength > proto.MaxBlob {
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	if p, err := s.st.Person(toUser); err != nil || p.State != store.Active {
		fail(w, http.StatusNotFound, "Refused.")
		return
	}
	if b, err := s.st.Blob(id); err == nil {
		// A retry of a file we already have: accept it if it is the same one.
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, proto.MaxBlob))
		if b.From == from && b.To == to {
			writeJSON(w, http.StatusOK, map[string]any{})
		} else {
			fail(w, http.StatusConflict, "Refused.")
		}
		return
	}
	h := sha256.New()
	b, err := s.st.PutBlob(id, from, to, io.TeeReader(http.MaxBytesReader(w, r.Body, proto.MaxBlob), h))
	if err != nil {
		fail(w, http.StatusBadRequest, "Refused.")
		return
	}
	if !s.fedSigned(r, f, key, h.Sum(nil)) {
		_ = s.st.DeleteBlob(b.ID)
		fail(w, http.StatusForbidden, "Refused.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}
