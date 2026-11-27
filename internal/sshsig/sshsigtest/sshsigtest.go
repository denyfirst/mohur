// Package sshsigtest signs like `ssh-keygen -Y sign`, for tests only: they
// need release lists signed by a key of their own.
package sshsigtest

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

func str(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v))) // #nosec G115 -- test data
	return append(b, v...)
}

// KeyText is the base64 key field for pub, as in an allowed_signers line.
func KeyText(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(str(str(nil, []byte("ssh-ed25519")), pub))
}

// Sign returns an armored SSHSIG of message in namespace.
func Sign(priv ed25519.PrivateKey, namespace string, message []byte) []byte {
	digest := sha512.Sum512(message)
	signed := []byte("SSHSIG")
	for _, v := range [][]byte{[]byte(namespace), nil, []byte("sha512"), digest[:]} {
		signed = str(signed, v)
	}
	blob := []byte("SSHSIG")
	blob = binary.BigEndian.AppendUint32(blob, 1)
	blob = str(blob, str(str(nil, []byte("ssh-ed25519")), priv.Public().(ed25519.PublicKey)))
	blob = str(blob, []byte(namespace))
	blob = str(blob, nil)
	blob = str(blob, []byte("sha512"))
	blob = str(blob, str(str(nil, []byte("ssh-ed25519")), ed25519.Sign(priv, signed)))
	b64 := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n-----END SSH SIGNATURE-----\n")
	return []byte(out.String())
}
