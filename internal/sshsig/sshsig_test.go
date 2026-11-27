package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// Made with OpenSSH on Windows from a throwaway key that was never kept:
//
//	ssh-keygen -t ed25519 -f testkey
//	ssh-keygen -Y sign -f testkey -n file msg
const (
	vectorKey     = "AAAAC3NzaC1lZDI1NTE5AAAAIO/l3wtzogK3PZ9FB2gUR3jm+5OTYGJoBz7lA4WQelps"
	vectorMessage = "mohurd_v0.1.0_linux_amd64 test\n"
	vectorSig     = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg7+XfC3OiArc9n0UHaBRHeOb7k5
NgYmgHPuUDhZB6WmwAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAECuOvTv1nFosnvG7GSO7ZYlmMW9jItG2frbwH4H0k/9e64mpplxdHtgqaDOrzIxzN
IEHgm4rSnP6FFK6szPBiYO
-----END SSH SIGNATURE-----
`
)

func str(b []byte, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v))) // #nosec G115 -- test data
	return append(b, v...)
}

func keyBlob(pub ed25519.PublicKey) []byte {
	return str(str(nil, []byte("ssh-ed25519")), pub)
}

// fields are the parts of a signature a test may change.
type fields struct {
	version  uint32
	key      []byte
	ns       string
	reserved string
	hash     string
	sigType  string
	sig      []byte // nil: sign properly
	trailer  []byte
}

// sign builds an SSHSIG the way ssh-keygen does, then lets a test bend it.
func sign(priv ed25519.PrivateKey, message []byte, f fields) []byte {
	if f.version == 0 {
		f.version = 1
	}
	if f.key == nil {
		f.key = keyBlob(priv.Public().(ed25519.PublicKey))
	}
	if f.ns == "" {
		f.ns = "file"
	}
	if f.hash == "" {
		f.hash = "sha512"
	}
	if f.sigType == "" {
		f.sigType = "ssh-ed25519"
	}
	var digest []byte
	if f.hash == "sha256" {
		h := sha256.Sum256(message)
		digest = h[:]
	} else {
		h := sha512.Sum512(message)
		digest = h[:]
	}
	signed := []byte("SSHSIG")
	for _, v := range [][]byte{[]byte(f.ns), []byte(f.reserved), []byte(f.hash), digest} {
		signed = str(signed, v)
	}
	sig := f.sig
	if sig == nil {
		sig = ed25519.Sign(priv, signed)
	}
	blob := []byte("SSHSIG")
	blob = binary.BigEndian.AppendUint32(blob, f.version)
	blob = str(blob, f.key)
	blob = str(blob, []byte(f.ns))
	blob = str(blob, []byte(f.reserved))
	blob = str(blob, []byte(f.hash))
	blob = str(blob, str(str(nil, []byte(f.sigType)), sig))
	blob = append(blob, f.trailer...)
	return armor(blob)
}

func armor(blob []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString(begin + "\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n" + end + "\n")
	return []byte(out.String())
}

func TestSignatureFromSSHKeygenVerifies(t *testing.T) {
	key, err := ParseKey(vectorKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(key, "file", []byte(vectorMessage), []byte(vectorSig)); err != nil {
		t.Fatalf("ssh-keygen's signature: %v", err)
	}
	// Windows line ends in the file change nothing.
	crlf := strings.ReplaceAll(vectorSig, "\n", "\r\n")
	if err := Verify(key, "file", []byte(vectorMessage), []byte(crlf)); err != nil {
		t.Fatalf("with CRLF: %v", err)
	}
	// One changed byte of the message, another namespace or another key fails.
	if Verify(key, "file", []byte(strings.Replace(vectorMessage, "0.1.0", "0.1.1", 1)), []byte(vectorSig)) == nil {
		t.Fatal("an altered message verified")
	}
	if Verify(key, "git", []byte(vectorMessage), []byte(vectorSig)) == nil {
		t.Fatal("a signature for the file namespace verified as git")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ParseKey(base64.StdEncoding.EncodeToString(keyBlob(pub)))
	if Verify(other, "file", []byte(vectorMessage), []byte(vectorSig)) == nil {
		t.Fatal("another key verified ssh-keygen's signature")
	}
}

func TestOnlyAProperSignatureByTheKeyVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, err := ParseKey(base64.StdEncoding.EncodeToString(keyBlob(pub)))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("abc  mohurd_v1.2.3_linux_amd64\n")
	for _, hash := range []string{"sha512", "sha256"} {
		if err := Verify(key, "file", msg, sign(priv, msg, fields{hash: hash})); err != nil {
			t.Fatalf("%s: %v", hash, err)
		}
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	bad := map[string][]byte{
		"signed by another key":          sign(otherPriv, msg, fields{}),
		"another key, claiming ours":     sign(otherPriv, msg, fields{key: keyBlob(pub)}),
		"another namespace":              sign(priv, msg, fields{ns: "git"}),
		"version 2":                      sign(priv, msg, fields{version: 2}),
		"a reserved field":               sign(priv, msg, fields{reserved: "x"}),
		"sha1":                           sign(priv, msg, fields{hash: "sha1"}),
		"an RSA signature type":          sign(priv, msg, fields{sigType: "rsa-sha2-512"}),
		"a short signature":              sign(priv, msg, fields{sig: make([]byte, 63)}),
		"a zero signature":               sign(priv, msg, fields{sig: make([]byte, 64)}),
		"bytes after the signature":      sign(priv, msg, fields{trailer: []byte{0}}),
		"text before the armor":          append([]byte("x\n"), sign(priv, msg, fields{})...),
		"text after the armor":           append(sign(priv, msg, fields{}), []byte("x\n")...),
		"no end line":                    bytes.TrimSuffix(sign(priv, msg, fields{}), []byte(end+"\n")),
		"broken base64":                  bytes.Replace(sign(priv, msg, fields{}), []byte("U1NI"), []byte("U1N*"), 1),
		"the wrong magic":                armor([]byte("SSHSIX\x00\x00\x00\x01")),
		"a length past the end":          armor([]byte("SSHSIG\x00\x00\x00\x01\xff\xff\xff\xff")),
		"empty":                          nil,
		"too long":                       append(sign(priv, msg, fields{}), bytes.Repeat([]byte("\n"), MaxArmored)...),
		"a signature of another message": sign(priv, []byte("abc  mohurd_v9.9.9_linux_amd64\n"), fields{}),
	}
	for name, sig := range bad {
		if Verify(key, "file", msg, sig) == nil {
			t.Errorf("%s verified", name)
		}
	}
	// A flipped bit anywhere in the signature bytes fails.
	good := sign(priv, msg, fields{})
	blob, _ := unarmor(good)
	for i := len(blob) - 64; i < len(blob); i += 7 {
		flipped := bytes.Clone(blob)
		flipped[i] ^= 1
		if Verify(key, "file", msg, armor(flipped)) == nil {
			t.Fatalf("flipped byte %d verified", i)
		}
	}
	if Verify(key, "", msg, good) == nil {
		t.Fatal("an empty namespace verified")
	}
	if Verify(Key{}, "file", msg, good) == nil {
		t.Fatal("no key verified")
	}
}

func TestKeysAreReadStrictly(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, b64 := range map[string]string{
		"not base64":      "AAAA*",
		"empty":           "",
		"an RSA key":      base64.StdEncoding.EncodeToString(str(str(nil, []byte("ssh-rsa")), pub)),
		"a short key":     base64.StdEncoding.EncodeToString(str(str(nil, []byte("ssh-ed25519")), pub[:31])),
		"bytes after key": base64.StdEncoding.EncodeToString(append(keyBlob(pub), 0)),
	} {
		if _, err := ParseKey(b64); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
