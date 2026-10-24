//wirenet:deterministic

// Package model holds the identifiers, keys and small value types every
// component shares.
package model

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Identifiers carry a prefix naming their kind, so a log line or a stray
// argument says what it refers to.
type (
	NetworkID   string
	ServiceID   string
	InterfaceID string
	HostID      string
	RelayID     string
	RuleID      string
	AdminID     string
)

// Prefixes of each kind of identifier.
const (
	NetworkPrefix   = "net-"
	ServicePrefix   = "svc-"
	InterfacePrefix = "if-"
	HostPrefix      = "host-"
	RelayPrefix     = "relay-"
	RulePrefix      = "rule-"
	AdminPrefix     = "admin-"
)

// idChars is 16 lowercase base32 characters, 80 bits.
const idChars = 16

// NewID draws an identifier with the given prefix from r.
func NewID(prefix string, r io.Reader) (string, error) {
	var b [10]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	return prefix + enc.EncodeToString(b[:])[:idChars], nil
}

// Short returns the random part of an identifier, which names its namespace
// and fits in kernel names.
func Short(id string) string {
	if i := strings.IndexByte(id, '-'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// Key is a Curve25519 key, private or public, as WireGuard uses.
type Key [32]byte

// ErrKeyLength reports a key that does not decode to 32 bytes.
var ErrKeyLength = errors.New("key must be 32 bytes")

// NewPrivateKey draws a clamped Curve25519 private key from r.
func NewPrivateKey(r io.Reader) (Key, error) {
	var k Key
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return Key{}, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// Public returns the public key of private key k.
func (k Key) Public() Key {
	var pub Key
	out, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// X25519 with the base point fails only for an all-zero output,
		// which no clamped scalar produces.
		panic(err)
	}
	copy(pub[:], out)
	return pub
}

// IsZero reports whether k is unset.
func (k Key) IsZero() bool { return k == Key{} }

// String encodes k in base64, as wg(8) prints keys.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// MarshalText encodes k in base64.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText decodes a base64 key.
func (k *Key) UnmarshalText(b []byte) error {
	parsed, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// ParseKey decodes a base64 key.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("key: %w", err)
	}
	if len(b) != 32 {
		return Key{}, ErrKeyLength
	}
	var k Key
	copy(k[:], b)
	return k, nil
}

// Secret is a 32-byte symmetric secret, such as a direction's registration
// secret.
type Secret [32]byte

// NewSecret draws a secret from r.
func NewSecret(r io.Reader) (Secret, error) {
	var s Secret
	_, err := io.ReadFull(r, s[:])
	return s, err
}

// MarshalText encodes s in base64.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(s[:])), nil
}

// UnmarshalText decodes a base64 secret.
func (s *Secret) UnmarshalText(b []byte) error {
	k, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*s = Secret(k)
	return nil
}

// Proto is a transport protocol a policy rule names.
type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
	// AnyProto permits every IP protocol, without ports.
	AnyProto Proto = "any"
	// OtherProto is every IP protocol but TCP and UDP, without ports. Rules
	// cannot name it; the compiler produces it when a deny takes TCP or UDP
	// flows out of an allow for any protocol.
	OtherProto Proto = "other"
)

// Valid reports whether p is a protocol a rule may name.
func (p Proto) Valid() bool { return p == TCP || p == UDP || p == AnyProto }

// Matches reports whether a grant for p over ports admits a packet of
// protocol proto to port.
func (p Proto) Matches(ports PortRange, proto Proto, port uint16) bool {
	switch p {
	case AnyProto:
		return true
	case OtherProto:
		return proto != TCP && proto != UDP
	}
	return p == proto && ports.Contains(port)
}

// AnyService is the wildcard a rule names in place of a service: every
// service of the network but the one on the rule's other side.
const AnyService ServiceID = "*"

// PortRange is an inclusive range of ports. A zero range means every port.
type PortRange struct {
	Lo uint16 `json:"lo"`
	Hi uint16 `json:"hi"`
}

// All reports whether the range covers every port.
func (r PortRange) All() bool { return r.Lo == 0 && r.Hi == 0 || r.Lo <= 1 && r.Hi == 65535 }

// Contains reports whether port lies in the range.
func (r PortRange) Contains(port uint16) bool { return r.All() || port >= r.Lo && port <= r.Hi }

// String prints the range as nftables does.
func (r PortRange) String() string {
	switch {
	case r.All():
		return "*"
	case r.Lo == r.Hi:
		return fmt.Sprint(r.Lo)
	default:
		return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
	}
}

// ParsePortRange parses "5432", "8000-8100" or "*".
func ParsePortRange(s string) (PortRange, error) {
	if s == "*" || s == "" {
		return PortRange{}, nil
	}
	lo, hi, ranged := strings.Cut(s, "-")
	if !ranged {
		hi = lo
	}
	l, errL := strconv.ParseUint(lo, 10, 16)
	h, errH := strconv.ParseUint(hi, 10, 16)
	if errL != nil || errH != nil || l == 0 || h < l {
		return PortRange{}, fmt.Errorf("bad port range %q", s)
	}
	return PortRange{Lo: uint16(l), Hi: uint16(h)}, nil
}
