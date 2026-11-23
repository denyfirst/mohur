// Package labdns is a tiny DNS server for tests and the local lab. It answers
// A and TXT questions from an in-memory zone and nothing else. Production
// servers use real DNS; this exists so the full discovery path, including the
// resolver, can run on one computer.
package labdns

import (
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// Server answers from a zone that can change while it runs.
type Server struct {
	conn *net.UDPConn
	mu   sync.RWMutex
	a    map[string]net.IP
	txt  map[string][]string
}

// Start listens on addr ("127.0.0.1:0" for any free port).
func Start(addr string) (*Server, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	s := &Server{conn: conn, a: map[string]net.IP{}, txt: map[string][]string{}}
	go s.serve()
	return s, nil
}

// Addr is the address to give resolvers.
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

// Close stops the server.
func (s *Server) Close() error { return s.conn.Close() }

func key(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// SetA sets a host's address.
func (s *Server) SetA(name string, ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.a[key(name)] = ip.To4()
}

// SetTXT replaces a name's TXT records; none removes them.
func (s *Server) SetTXT(name string, values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(values) == 0 {
		delete(s.txt, key(name))
		return
	}
	s.txt[key(name)] = values
}

func (s *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if out := s.answer(buf[:n]); out != nil {
			_, _ = s.conn.WriteToUDP(out, from)
		}
	}
}

func (s *Server) answer(req []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	name := key(q.Name.String())
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 1}
	s.mu.RLock()
	found := false
	switch q.Type {
	case dnsmessage.TypeA:
		if ip, ok := s.a[name]; ok && ip != nil {
			var a [4]byte
			copy(a[:], ip)
			_ = b.AResource(rh, dnsmessage.AResource{A: a})
			found = true
		}
	case dnsmessage.TypeTXT:
		for _, v := range s.txt[name] {
			_ = b.TXTResource(rh, dnsmessage.TXTResource{TXT: []string{v}})
			found = true
		}
	}
	_, known := s.a[name]
	if _, ok := s.txt[name]; ok {
		known = true
	}
	s.mu.RUnlock()
	if !found && !known {
		// NXDOMAIN, so lookups fail fast instead of timing out.
		b2 := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RCode: dnsmessage.RCodeNameError, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
		_ = b2.StartQuestions()
		_ = b2.Question(q)
		out, _ := b2.Finish()
		return out
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
