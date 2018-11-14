// Package multihash is the Go implementation of
// https://github.com/multiformats/multihash, or self-describing
// hashes.
package multihash

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	strbinary "github.com/multiformats/go-multihash/strbinary"

	b58 "github.com/mr-tron/base58/base58"
)

// errors
var (
	ErrUnknownCode      = errors.New("unknown multihash code")
	ErrTooShort         = errors.New("multihash too short. must be >= 2 bytes")
	ErrTooLong          = errors.New("multihash too long. must be < 129 bytes")
	ErrLenNotSupported  = errors.New("multihash does not yet support digests longer than 127 bytes")
	ErrInvalidMultihash = errors.New("input isn't valid multihash")

	ErrVarintBufferShort = errors.New("uvarint: buffer too small")
	ErrVarintTooLong     = errors.New("uvarint: varint too big (max 64bit)")
)

// Nil represents an empty multihash value.
var Nil = Multihash{}

// ErrInconsistentLen is returned when a decoded multihash has an inconsistent length
type ErrInconsistentLen struct {
	dm *DecodedMultihash
}

func (e ErrInconsistentLen) Error() string {
	return fmt.Sprintf("multihash length inconsistent: %v", e.dm)
}

// constants
const (
	ID         = 0x00
	SHA1       = 0x11
	SHA2_256   = 0x12
	SHA2_512   = 0x13
	SHA3_224   = 0x17
	SHA3_256   = 0x16
	SHA3_384   = 0x15
	SHA3_512   = 0x14
	SHA3       = SHA3_512
	KECCAK_224 = 0x1A
	KECCAK_256 = 0x1B
	KECCAK_384 = 0x1C
	KECCAK_512 = 0x1D

	SHAKE_128 = 0x18
	SHAKE_256 = 0x19

	BLAKE2B_MIN = 0xb201
	BLAKE2B_MAX = 0xb240
	BLAKE2S_MIN = 0xb241
	BLAKE2S_MAX = 0xb260

	DBL_SHA2_256 = 0x56

	MURMUR3 = 0x22
)

func init() {
	// Add blake2b (64 codes)
	for c := uint64(BLAKE2B_MIN); c <= BLAKE2B_MAX; c++ {
		n := c - BLAKE2B_MIN + 1
		name := fmt.Sprintf("blake2b-%d", n*8)
		Names[name] = c
		Codes[c] = name
		DefaultLengths[c] = int(n)
	}

	// Add blake2s (32 codes)
	for c := uint64(BLAKE2S_MIN); c <= BLAKE2S_MAX; c++ {
		n := c - BLAKE2S_MIN + 1
		name := fmt.Sprintf("blake2s-%d", n*8)
		Names[name] = c
		Codes[c] = name
		DefaultLengths[c] = int(n)
	}
}

// Names maps the name of a hash to the code
var Names = map[string]uint64{
	"id":           ID,
	"sha1":         SHA1,
	"sha2-256":     SHA2_256,
	"sha2-512":     SHA2_512,
	"sha3":         SHA3_512,
	"sha3-224":     SHA3_224,
	"sha3-256":     SHA3_256,
	"sha3-384":     SHA3_384,
	"sha3-512":     SHA3_512,
	"dbl-sha2-256": DBL_SHA2_256,
	"murmur3":      MURMUR3,
	"keccak-224":   KECCAK_224,
	"keccak-256":   KECCAK_256,
	"keccak-384":   KECCAK_384,
	"keccak-512":   KECCAK_512,
	"shake-128":    SHAKE_128,
	"shake-256":    SHAKE_256,
}

// Codes maps a hash code to it's name
var Codes = map[uint64]string{
	ID:           "id",
	SHA1:         "sha1",
	SHA2_256:     "sha2-256",
	SHA2_512:     "sha2-512",
	SHA3_224:     "sha3-224",
	SHA3_256:     "sha3-256",
	SHA3_384:     "sha3-384",
	SHA3_512:     "sha3-512",
	DBL_SHA2_256: "dbl-sha2-256",
	MURMUR3:      "murmur3",
	KECCAK_224:   "keccak-224",
	KECCAK_256:   "keccak-256",
	KECCAK_384:   "keccak-384",
	KECCAK_512:   "keccak-512",
	SHAKE_128:    "shake-128",
	SHAKE_256:    "shake-256",
}

// DefaultLengths maps a hash code to it's default length
var DefaultLengths = map[uint64]int{
	ID:           -1,
	SHA1:         20,
	SHA2_256:     32,
	SHA2_512:     64,
	SHA3_224:     28,
	SHA3_256:     32,
	SHA3_384:     48,
	SHA3_512:     64,
	DBL_SHA2_256: 32,
	KECCAK_224:   28,
	KECCAK_256:   32,
	MURMUR3:      4,
	KECCAK_384:   48,
	KECCAK_512:   64,
	SHAKE_128:    32,
	SHAKE_256:    64,
}

func uvarint(buf []byte) (uint64, []byte, error) {
	n, c := binary.Uvarint(buf)

	if c == 0 {
		return n, buf, ErrVarintBufferShort
	} else if c < 0 {
		return n, buf[-c:], ErrVarintTooLong
	} else {
		return n, buf[c:], nil
	}
}

// DecodedMultihash represents a parsed multihash and allows
// easy access to the different parts of a multihash.
type DecodedMultihash struct {
	Code   uint64
	Name   string
	Length int    // Length is just int as it is type of len() opearator
	Digest []byte // Digest holds the raw multihash bytes
}

// Multihash is the cannoical representation of a Multihash
// It is repressed internally as a binary with the following form:
// <hash function code><digest size><hash function output>.
// See the spec for more information.
type Multihash struct {
	s string
}

// HexString returns the hex-encoded representation of a multihash.
func (m Multihash) HexString() string {
	return hex.EncodeToString([]byte(m.s))
}

// String is an alias to HexString().
func (m Multihash) String() string {
	return m.HexString()
}

// Bytes returns the multihash as a byte slice.
func (m Multihash) Bytes() []byte {
	return []byte(m.s)
}

// IsNil returns true if the multihash is empty.
func (m Multihash) IsNil() bool {
	return m.s == ""
}

// Binary returns the multihash as a binary string.
//
// Unlike `bytes`, this doesn't allocate.
func (m Multihash) Binary() string {
	return m.s
}

// FromHexString parses a hex-encoded multihash.
func FromHexString(s string) (Multihash, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Multihash{}, err
	}

	return Cast(b)
}

// B58String returns the B58-encoded representation of a multihash.
func (m Multihash) B58String() string {
	return b58.Encode([]byte(m.s))
}

// FromB58String parses a B58-encoded multihash.
func FromB58String(s string) (m Multihash, err error) {
	b, err := b58.Decode(s)
	if err != nil {
		return Multihash{}, ErrInvalidMultihash
	}

	return Cast(b)
}

// FromBinary creates a new multihash from the binary representation.
func FromBinary(v string) (Multihash, error) {
	if len(v) < 2 {
		return Nil, ErrTooShort
	}
	i := 0
	codec, l := strbinary.Uvarint(v)
	if l <= 0 {
		return Nil, ErrInvalidMultihash
	}
	if !ValidCode(codec) {
		return Nil, ErrUnknownCode
	}
	i += l
	digestLen, l := strbinary.Uvarint(v[i:])
	i += l
	if l <= 0 || len(v[i:]) != int(digestLen) {
		return Nil, ErrInvalidMultihash
	}
	return Multihash{v}, nil
}

// Parts returns the components of the Multihash: the Code and Digest.
// The length part can be derived from the Digest length.
func (m Multihash) Parts() (uint64, string) {
	// Note: no need to check for errors as the FromBinary method guarantees
	// the string can be parsed
	codec, i := strbinary.Uvarint(m.s)
	// skip over Length component, no need to read it
	i += strbinary.UvarintLen(m.s[i:])
	return codec, m.s[i:]
}

// Cast casts a buffer onto a multihash, and returns an error
// if it does not work.
func Cast(buf []byte) (Multihash, error) {
	dm, err := Decode(buf)
	if err != nil {
		return Multihash{}, err
	}

	if !ValidCode(dm.Code) {
		return Multihash{}, ErrUnknownCode
	}

	return Multihash{s: string(buf)}, nil
}

// Decode parses multihash bytes into a DecodedMultihash.
func Decode(buf []byte) (*DecodedMultihash, error) {

	if len(buf) < 2 {
		return nil, ErrTooShort
	}

	var err error
	var code, length uint64

	code, buf, err = uvarint(buf)
	if err != nil {
		return nil, err
	}

	length, buf, err = uvarint(buf)
	if err != nil {
		return nil, err
	}

	if length > math.MaxInt32 {
		return nil, errors.New("digest too long, supporting only <= 2^31-1")
	}

	dm := &DecodedMultihash{
		Code:   code,
		Name:   Codes[code],
		Length: int(length),
		Digest: buf,
	}

	if len(dm.Digest) != dm.Length {
		return nil, ErrInconsistentLen{dm}
	}

	return dm, nil
}

// Encode a hash digest along with the specified function code.
// Note: the length is derived from the length of the digest itself.
func Encode(buf []byte, code uint64) ([]byte, error) {

	if !ValidCode(code) {
		return nil, ErrUnknownCode
	}

	start := make([]byte, 2*binary.MaxVarintLen64)
	spot := start
	n := binary.PutUvarint(spot, code)
	spot = start[n:]
	n += binary.PutUvarint(spot, uint64(len(buf)))

	return append(start[:n], buf...), nil
}

// EncodeName is like Encode() but providing a string name
// instead of a numeric code. See Names for allowed values.
func EncodeName(buf []byte, name string) ([]byte, error) {
	return Encode(buf, Names[name])
}

// ValidCode checks whether a multihash code is valid.
func ValidCode(code uint64) bool {
	if AppCode(code) {
		return true
	}

	if _, ok := Codes[code]; ok {
		return true
	}

	return false
}

// AppCode checks whether a multihash code is part of the App range.
func AppCode(code uint64) bool {
	return code >= 0 && code < 0x10
}
