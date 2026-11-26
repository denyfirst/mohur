// Package sshsig checks a signature made by `ssh-keygen -Y sign` with an
// Ed25519 key, the way denyfirst signs every release. It reads OpenSSH's
// SSHSIG format (PROTOCOL.sshsig) strictly and leaves the cryptography to
// crypto/ed25519; it signs nothing.
//
// Anyone can check the same signature without Mohur:
//
//	ssh-keygen -Y verify -f .allowed_signers -I releases@denyfirst.dev \
//	           -n file -s SHA256SUMS.sig < SHA256SUMS
package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// MaxArmored is the most a signature file may hold. An Ed25519 one is about
// 300 bytes.
const MaxArmored = 4 << 10

// ErrInvalid is every reason a signature is not accepted. Callers learn only
// that it did not verify.
var ErrInvalid = errors.New("signature does not verify")

const (
	magic   = "SSHSIG"
	begin   = "-----BEGIN SSH SIGNATURE-----"
	end     = "-----END SSH SIGNATURE-----"
	keyType = "ssh-ed25519"
)

// Key is a trusted Ed25519 public key.
type Key struct {
	blob []byte
	pub  ed25519.PublicKey
}

// ParseKey reads the base64 key field of an allowed_signers or .pub line.
func ParseKey(b64 string) (Key, error) {
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return Key{}, ErrInvalid
	}
	pub, err := parseKeyBlob(blob)
	if err != nil {
		return Key{}, err
	}
	return Key{blob: blob, pub: pub}, nil
}

func parseKeyBlob(blob []byte) (ed25519.PublicKey, error) {
	r := reader{b: blob}
	typ := r.string()
	raw := r.string()
	if r.bad || len(r.b) != 0 || string(typ) != keyType || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(raw), nil
}

// Verify checks that armored is key's signature of message in namespace.
func Verify(key Key, namespace string, message, armored []byte) error {
	if len(key.pub) != ed25519.PublicKeySize || namespace == "" || len(armored) > MaxArmored {
		return ErrInvalid
	}
	blob, err := unarmor(armored)
	if err != nil {
		return err
	}
	r := reader{b: blob}
	if !bytes.HasPrefix(r.b, []byte(magic)) {
		return ErrInvalid
	}
	r.b = r.b[len(magic):]
	version := r.uint32()
	pubBlob := r.string()
	ns := r.string()
	reserved := r.string()
	hashAlg := r.string()
	sigBlob := r.string()
	if r.bad || len(r.b) != 0 || version != 1 {
		return ErrInvalid
	}
	// The key in the signature must be the trusted key, byte for byte, and
	// the namespace the one the caller expects, so that a signature made for
	// another purpose with the same key is not accepted here.
	if !bytes.Equal(pubBlob, key.blob) || string(ns) != namespace || len(reserved) != 0 {
		return ErrInvalid
	}
	var digest []byte
	switch string(hashAlg) {
	case "sha512":
		h := sha512.Sum512(message)
		digest = h[:]
	case "sha256":
		h := sha256.Sum256(message)
		digest = h[:]
	default:
		return ErrInvalid
	}
	s := reader{b: sigBlob}
	sigType := s.string()
	sig := s.string()
	if s.bad || len(s.b) != 0 || string(sigType) != keyType || len(sig) != ed25519.SignatureSize {
		return ErrInvalid
	}
	signed := []byte(magic)
	for _, field := range [][]byte{ns, reserved, hashAlg, digest} {
		signed = binary.BigEndian.AppendUint32(signed, uint32(len(field))) // #nosec G115 -- fields are bounded by MaxArmored
		signed = append(signed, field...)
	}
	if !ed25519.Verify(key.pub, signed, sig) {
		return ErrInvalid
	}
	return nil
}

// unarmor takes the base64 body between the BEGIN and END lines; nothing may
// come before or after them but line ends.
func unarmor(armored []byte) ([]byte, error) {
	text := strings.ReplaceAll(string(armored), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	lines := strings.Split(text, "\n")
	if len(lines) < 3 || lines[0] != begin || lines[len(lines)-1] != end {
		return nil, ErrInvalid
	}
	body := strings.Join(lines[1:len(lines)-1], "")
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, ErrInvalid
	}
	return blob, nil
}

// reader reads SSH wire fields; any short read marks it bad.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) uint32() uint32 {
	if r.bad || len(r.b) < 4 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) string() []byte {
	n := r.uint32()
	if r.bad || uint64(n) > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
