package proto

import (
	"crypto/ed25519"
	"strconv"
	"strings"
	"time"
)

// OrgDoc is served at /.well-known/mohur and says who runs this server.
type OrgDoc struct {
	V      int    `json:"v"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Server string `json:"server"`
	Key    string `json:"key"`
	Sig    string `json:"sig"`
}

// SignOrg fills in the document's signature.
func SignOrg(d *OrgDoc, key ed25519.PrivateKey) {
	d.V = 1
	d.Sig = Sign(key, ContextOrg, d.Domain, d.Name, d.Server, d.Key)
}

// Check validates every field and the signature, and returns the key.
func (d OrgDoc) Check() (ed25519.PublicKey, error) {
	key, err := PublicKey(d.Key)
	if err != nil || d.V != 1 {
		return nil, ErrInvalid
	}
	domain, err := Domain(d.Domain)
	if err != nil || domain != d.Domain {
		return nil, ErrInvalid
	}
	if s, err := ServerName(d.Server, d.Domain); err != nil || s != d.Server {
		return nil, ErrInvalid
	}
	if n, ok := DisplayName(d.Name); !ok || n != d.Name {
		return nil, ErrInvalid
	}
	if !Verify(key, d.Sig, ContextOrg, d.Domain, d.Name, d.Server, d.Key) {
		return nil, ErrInvalid
	}
	return key, nil
}

// TXT is the content of the _mohur.<domain> record.
type TXT struct {
	Server string
	Key    ed25519.PublicKey
}

// TXTValue is the record text an admin adds to DNS.
func TXTValue(server string, key ed25519.PublicKey) string {
	return "v=mohur1 server=" + server + " key=" + B64(key)
}

// ParseTXT reads the record for domain. Exactly one record must start with
// v=mohur1; two would leave the choice to whoever answers DNS.
func ParseTXT(records []string, domain string) (TXT, error) {
	var found []string
	for _, r := range records {
		if r == "v=mohur1" || strings.HasPrefix(r, "v=mohur1 ") {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return TXT{}, ErrInvalid
	}
	fields := strings.Fields(found[0])
	var out TXT
	seen := map[string]bool{}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok || seen[k] {
			return TXT{}, ErrInvalid
		}
		seen[k] = true
		switch k {
		case "server":
			s, err := ServerName(v, domain)
			if err != nil {
				return TXT{}, ErrInvalid
			}
			out.Server = s
		case "key":
			key, err := PublicKey(v)
			if err != nil {
				return TXT{}, ErrInvalid
			}
			out.Key = key
		default:
			// Unknown fields are ignored so the record can grow.
		}
	}
	if out.Server == "" || out.Key == nil {
		return TXT{}, ErrInvalid
	}
	return out, nil
}

// DeviceCert is the organization's statement that a device belongs to a person.
type DeviceCert struct {
	Address     string `json:"address"`
	Name        string `json:"name"`
	Device      uint32 `json:"device"`
	IdentityKey string `json:"identityKey"`
	AuthKey     string `json:"authKey"`
	Issued      int64  `json:"issued"`
	Sig         string `json:"sig"`
}

func (c DeviceCert) fields() []string {
	return []string{c.Address, c.Name, strconv.FormatUint(uint64(c.Device), 10), c.IdentityKey, c.AuthKey, strconv.FormatInt(c.Issued, 10)}
}

// SignDevice fills in the certificate's signature.
func SignDevice(c *DeviceCert, key ed25519.PrivateKey) {
	c.Sig = Sign(key, ContextDevice, c.fields()...)
}

// IdentityKeyBytes is the serialized libsignal public key: a 0x05 type byte
// and 32 bytes.
func IdentityKeyBytes(s string) ([]byte, error) {
	b, err := UnB64(s)
	if err != nil || len(b) != 33 || b[0] != 0x05 {
		return nil, ErrInvalid
	}
	return b, nil
}

// Check validates the certificate against the organization key and domain.
func (c DeviceCert) Check(org ed25519.PublicKey, domain string) error {
	_, d, err := Address(c.Address)
	if err != nil || d != domain || c.Device < 1 || c.Device > 1<<20 || c.Issued <= 0 {
		return ErrInvalid
	}
	if n, ok := DisplayName(c.Name); !ok || n != c.Name {
		return ErrInvalid
	}
	if _, err := IdentityKeyBytes(c.IdentityKey); err != nil {
		return ErrInvalid
	}
	if _, err := PublicKey(c.AuthKey); err != nil {
		return ErrInvalid
	}
	if !Verify(org, c.Sig, ContextDevice, c.fields()...) {
		return ErrInvalid
	}
	return nil
}

// Envelope carries one libsignal ciphertext from one device to another.
// Servers fill in ID, From, FromDevice, FromCert and Time; the app only
// chooses the recipient and the ciphertext.
type Envelope struct {
	ID         string     `json:"id"`
	From       string     `json:"from"`
	FromDevice uint32     `json:"fromDevice"`
	FromCert   DeviceCert `json:"fromCert"`
	To         string     `json:"to"`
	ToDevice   uint32     `json:"toDevice"`
	Type       int        `json:"type"`
	Body       string     `json:"body"`
	Blobs      []string   `json:"blobs,omitempty"`
	Time       int64      `json:"time"`
}

// Ciphertext types, as libsignal numbers them.
const (
	TypeWhisper = 2
	TypePreKey  = 3
)

// Limits shared by servers and apps.
const (
	MaxBody          = 256 << 10
	MaxBlobsPerEnv   = 4
	MaxBlob          = 100<<20 + 64
	MaxEnvelopesSend = 32
	QueueLifetime    = 30 * 24 * time.Hour
	FedClockSkew     = 5 * time.Minute
)

// CheckShape validates the parts of an envelope a sender controls.
func (e Envelope) CheckShape() error {
	if _, _, err := Address(e.To); err != nil || e.ToDevice < 1 || e.ToDevice > 1<<20 {
		return ErrInvalid
	}
	if e.Type != TypeWhisper && e.Type != TypePreKey {
		return ErrInvalid
	}
	body, err := UnB64(e.Body)
	if err != nil || len(body) == 0 || len(body) > MaxBody {
		return ErrInvalid
	}
	if len(e.Blobs) > MaxBlobsPerEnv {
		return ErrInvalid
	}
	for _, b := range e.Blobs {
		if !ID(b) {
			return ErrInvalid
		}
	}
	return nil
}

// ID reports whether s is a server-made identifier: 16 random bytes, base64url.
func ID(s string) bool {
	b, err := UnB64(s)
	return err == nil && len(b) == 16
}

// PreKey is a public one-time or signed prekey as the app uploaded it.
type PreKey struct {
	ID  uint32 `json:"id"`
	Pub string `json:"pub"`
	Sig string `json:"sig,omitempty"`
}

// Bundle is what a sender needs to start a session with one device.
type Bundle struct {
	Cert           DeviceCert `json:"cert"`
	RegistrationID uint32     `json:"registrationId"`
	PreKey         *PreKey    `json:"preKey,omitempty"`
	SignedPreKey   PreKey     `json:"signedPreKey"`
	KyberPreKey    PreKey     `json:"kyberPreKey"`
}

// Person is one entry in a directory.
type Person struct {
	Address string       `json:"address"`
	Name    string       `json:"name"`
	Devices []DeviceCert `json:"devices"`
}
