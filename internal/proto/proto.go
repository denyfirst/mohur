// Package proto holds the values Mohur servers and apps exchange and the one
// way they are signed. Every signature covers a context label and the fields,
// each written as a 4-byte big-endian length and its bytes, so Go and the
// desktop app build the same bytes without any JSON canonicalization.
package proto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Signature contexts. A value signed for one can never verify as another.
const (
	ContextOrg     = "mohur/org/v1"
	ContextDevice  = "mohur/device/v1"
	ContextFed     = "mohur/fed/v1"
	ContextSession = "mohur/session/v1"
)

// ErrInvalid is returned for any value that fails validation. Callers never
// learn which field was wrong from it; the reason is not useful to an attacker
// and the honest sender built the value with the same code.
var ErrInvalid = errors.New("invalid value")

// SignedBytes is the exact byte string a signature covers.
func SignedBytes(context string, fields ...string) []byte {
	size := 4 + len(context)
	for _, f := range fields {
		size += 4 + len(f)
	}
	out := make([]byte, 0, size)
	out = binary.BigEndian.AppendUint32(out, uint32(len(context))) // #nosec G115 -- contexts are short constants
	out = append(out, context...)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f))) // #nosec G115 -- fields are bounded by request limits far below 4 GiB
		out = append(out, f...)
	}
	return out
}

// Sign signs the fields under context.
func Sign(key ed25519.PrivateKey, context string, fields ...string) string {
	return B64(ed25519.Sign(key, SignedBytes(context, fields...)))
}

// Verify reports whether sig is key's signature of the fields under context.
func Verify(key ed25519.PublicKey, sig, context string, fields ...string) bool {
	raw, err := UnB64(sig)
	if err != nil || len(raw) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(key, SignedBytes(context, fields...), raw)
}

// B64 is unpadded base64url, the only binary encoding on the wire.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64 decodes unpadded base64url and refuses any other spelling.
func UnB64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || B64(b) != s {
		return nil, ErrInvalid
	}
	return b, nil
}

// PublicKey decodes an Ed25519 public key.
func PublicKey(s string) (ed25519.PublicKey, error) {
	b, err := UnB64(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(b), nil
}

// Fingerprint is a short, readable form of an organization key for people
// who want to compare it: twelve groups of five digits from its SHA-256.
func Fingerprint(a, b ed25519.PublicKey) string {
	// Order the two keys so both sides compute the same code.
	first, second := a, b
	if string(b) < string(a) {
		first, second = b, a
	}
	sum := sha512.Sum512(SignedBytes("mohur/fingerprint/v1", string(first), string(second)))
	groups := make([]string, 12)
	for i := range groups {
		var chunk [8]byte
		copy(chunk[3:], sum[5*i:5*i+5])
		groups[i] = fmt.Sprintf("%05d", binary.BigEndian.Uint64(chunk[:])%100000)
	}
	return strings.Join(groups, " ")
}

var profile = idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.Transitional(false), idna.BidiRule(), idna.VerifyDNSLength(true))

// Domain returns the lowercase ASCII form of a domain name a person typed,
// or ErrInvalid. Internationalized names become their xn-- form. A domain
// needs at least two labels; IP addresses, ports and trailing dots are refused.
func Domain(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 || strings.HasSuffix(s, ".") || strings.ContainsAny(s, ":/@ ") {
		return "", ErrInvalid
	}
	ascii, err := profile.ToASCII(s)
	if err != nil || ascii == "" || net.ParseIP(ascii) != nil || !strings.Contains(ascii, ".") {
		return "", ErrInvalid
	}
	ascii = strings.ToLower(ascii)
	for _, label := range strings.Split(ascii, ".") {
		if !label63(label) {
			return "", ErrInvalid
		}
	}
	return ascii, nil
}

func label63(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// ServerName checks a server address, a host name with an optional port, and
// requires the host to be the domain or a name under it. That rule is what
// stops a forged DNS answer from sending a partner to someone else's server:
// the forger would also need a certificate for a name under the domain.
func ServerName(server, domain string) (string, error) {
	host, port := server, ""
	if h, p, err := net.SplitHostPort(server); err == nil {
		host, port = h, p
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return "", ErrInvalid
		}
	}
	h, err := Domain(host)
	if err != nil || h != host || (h != domain && !strings.HasSuffix(h, "."+domain)) {
		return "", ErrInvalid
	}
	if port != "" {
		return net.JoinHostPort(h, port), nil
	}
	return h, nil
}

// Username is the local part of an address: a lowercase letter or digit, then
// up to 31 of letters, digits, dot, dash and underscore.
func Username(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '.' || c == '-' || c == '_'))
		if !ok {
			return false
		}
	}
	return true
}

// Address splits user@domain and validates both parts.
func Address(s string) (user, domain string, err error) {
	at := strings.IndexByte(s, '@')
	if at < 0 || strings.Count(s, "@") != 1 {
		return "", "", ErrInvalid
	}
	user, domain = s[:at], s[at+1:]
	d, derr := Domain(domain)
	if !Username(user) || derr != nil || d != domain {
		return "", "", ErrInvalid
	}
	return user, domain, nil
}

// DisplayName is a person's or organization's name as shown: 1 to 80
// characters, no control characters, trimmed.
func DisplayName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > 80 || strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
	}) {
		return "", false
	}
	return s, true
}
