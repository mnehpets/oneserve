package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crypto/cipher"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrCookieFormat  = errors.New("invalid session cookie format")
	ErrCookieInvalid = errors.New("invalid session cookie")
	ErrCookieConfig  = errors.New("invalid secure cookie configuration")
)

// maxCookieLen bounds the amount of attacker-controlled data we will
// decode/allocate for a cookie value. Browsers typically cap individual cookie
// values around 4KB, but we enforce our own limit defensively.
const maxCookieLen = 8192

// defaultAEADKeysize is the expected key size (in bytes) for the default
// AEAD implementation (chacha20poly1305). Exposed as a package-scoped var
// so callers/tests can reference the default key length.
const DefaultAEADKeysize = chacha20poly1305.KeySize

// SecureCookie is a codec for sealing/unsealing cookie values.
type SecureCookie interface {
	// Name returns the cookie name used by this codec.
	Name() string
	Encode(plain any, maxAge int) (*http.Cookie, error)
	Decode(cookie *http.Cookie, v any) error
	// Clear returns an http.Cookie that clears this cookie in the client.
	Clear() *http.Cookie
}

// SecureCookieCodec handles the encryption/decryption of values.
type SecureCookieCodec struct {
	KeyID string
	Keys  map[string][]byte

	// NewAEAD constructs the AEAD used to seal/open cookies.
	// Defaults to chacha20poly1305.NewX.
	NewAEAD func(key []byte) (cipher.AEAD, error)
}

// NewSecureCookieCodec creates a new codec.
func NewSecureCookieCodec(keyID string, keys map[string][]byte, newAEAD func(key []byte) (cipher.AEAD, error)) (*SecureCookieCodec, error) {
	if keys == nil {
		return nil, errors.New("keys must not be nil")
	}
	if _, ok := keys[keyID]; !ok {
		return nil, errors.New("keyID not found in keys")
	}
	if newAEAD == nil {
		return nil, errors.New("newAEAD must not be nil")
	}
	// Validate keys.
	for id, k := range keys {
		if _, err := newAEAD(k); err != nil {
			return nil, fmt.Errorf("invalid key %s: %w", id, err)
		}
	}
	return &SecureCookieCodec{
		KeyID:   keyID,
		Keys:    keys,
		NewAEAD: newAEAD,
	}, nil
}

// Encode encrypts plainBytes. aad should be unique to the context (e.g. cookie name + path).
func (sc *SecureCookieCodec) Encode(plainBytes []byte, aad []byte) (string, error) {
	if sc == nil {
		return "", ErrCookieConfig
	}
	key, ok := sc.Keys[sc.KeyID]
	if !ok {
		return "", ErrCookieConfig
	}
	aead, err := sc.NewAEAD(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	encrypted := aead.Seal(nonce, nonce, plainBytes, aad)
	return sc.KeyID + "." + base64.RawURLEncoding.EncodeToString(encrypted), nil
}

// Decode decrypts value.
func (sc *SecureCookieCodec) Decode(value string, aad []byte) ([]byte, error) {
	if sc == nil {
		return nil, ErrCookieConfig
	}
	if len(value) == 0 || len(value) > maxCookieLen {
		return nil, ErrCookieFormat
	}
	keyID, encB64, ok := strings.Cut(value, ".")
	if !ok || keyID == "" || encB64 == "" {
		return nil, ErrCookieFormat
	}
	key, ok := sc.Keys[keyID]
	if !ok {
		return nil, ErrCookieInvalid
	}

	encrypted, err := base64.RawURLEncoding.DecodeString(encB64)
	if err != nil {
		return nil, ErrCookieFormat
	}

	aead, err := sc.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrCookieFormat
	}
	nonce, ciphertext := encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():]
	b, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrCookieInvalid
	}
	return b, nil
}

// SecureCookieAEAD is a SecureCookie implementation that uses
// a supplied AEAD for authenticated encryption.
//
// Format: [keyId] "." [sealed_b64]
// where sealed = nonce || AEAD.Seal(nil, nonce, plaintext, aad)
// and aad = cookieName ":" .
// Key rotation: keys contains all accepted keys; keyID selects the current
// encryption key for sealing.
//
// The nonce is randomly generated per-cookie.
type SecureCookieAEAD struct {
	name     string
	path     string
	domain   string
	secure   bool
	sameSite http.SameSite

	Codec *SecureCookieCodec

	marshal   func(any) ([]byte, error)
	unmarshal func([]byte, any) error
	newAEAD   func([]byte) (cipher.AEAD, error)
}

// Name returns the cookie name.
func (sc *SecureCookieAEAD) Name() string {
	if sc == nil {
		return ""
	}
	return sc.name
}

// SecureCookieOption configures the SecureCookie.
type SecureCookieOption func(*SecureCookieAEAD)

// WithMarshalUnmarshal configures custom marshal/unmarshal functions.
func WithMarshalUnmarshal(marshal func(any) ([]byte, error), unmarshal func([]byte, any) error) SecureCookieOption {
	return func(sc *SecureCookieAEAD) {
		sc.marshal = marshal
		sc.unmarshal = unmarshal
	}
}

// WithAEAD configures the cookie to use a custom AEAD factory (e.g. AES-GCM).
func WithAEAD(f func([]byte) (cipher.AEAD, error)) SecureCookieOption {
	return func(sc *SecureCookieAEAD) {
		sc.newAEAD = f
	}
}

// WithPath configures the cookie path.
func WithPath(path string) SecureCookieOption {
	return func(sc *SecureCookieAEAD) {
		sc.path = path
	}
}

// WithDomain configures the cookie domain.
func WithDomain(domain string) SecureCookieOption {
	return func(sc *SecureCookieAEAD) {
		sc.domain = domain
	}
}

// WithSecure configures the cookie secure flag.
func WithSecure(secure bool) SecureCookieOption {
	return func(sc *SecureCookieAEAD) {
		sc.secure = secure
	}
}

// WithSameSite configures the cookie sameSite attribute.
func WithSameSite(sameSite http.SameSite) SecureCookieOption {
	return func(sc *SecureCookieAEAD) {
		sc.sameSite = sameSite
	}
}

// NewSecureCookie creates a SecureCookie using default configuration.
// It uses SecureCookieAEAD with ChaCha20Poly1305 and CBOR encoding.
//
// Defaults:
//   - Domain: ""
//   - Path: /
//   - HttpOnly: true
//   - Secure: true
//   - SameSite: Lax

func NewSecureCookie(cookieName string, keyID string, keys map[string][]byte, opts ...SecureCookieOption) (*SecureCookieAEAD, error) {
	sc := &SecureCookieAEAD{
		name:      cookieName,
		marshal:   cbor.Marshal,
		unmarshal: cbor.Unmarshal,
		newAEAD:   chacha20poly1305.NewX,
		domain:    "",
		path:      "/",
		secure:    true,
		sameSite:  http.SameSiteLaxMode,
	}
	for _, opt := range opts {
		opt(sc)
	}

	codec, err := NewSecureCookieCodec(keyID, keys, sc.newAEAD)
	if err != nil {
		return nil, err
	}
	sc.Codec = codec

	if sc.path == "" {
		sc.path = "/"
	}

	return sc, nil
}

// aad calculates the additional authenticated data for this cookie.
// This data binds the cookie name, domain, path and secure flag to
// the encoded value.
func (sc *SecureCookieAEAD) aad() []byte {
	secureStr := "f"
	if sc.secure {
		secureStr = "t"
	}
	return []byte(sc.name + ":" + sc.domain + ":" + sc.path + ":" + secureStr)
}

// Encode marshals and seals plain and returns an http.Cookie carrying the value.
func (sc *SecureCookieAEAD) Encode(plain any, maxAge int) (*http.Cookie, error) {
	if maxAge <= 0 {
		return nil, ErrCookieInvalid
	}
	if sc.Codec == nil || sc.marshal == nil {
		return nil, ErrCookieConfig
	}

	plainBytes, err := sc.marshal(plain)
	if err != nil {
		return nil, err
	}

	val, err := sc.Codec.Encode(plainBytes, sc.aad())
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     sc.name,
		Value:    val,
		Path:     sc.path,
		Domain:   sc.domain,
		MaxAge:   maxAge,
		Secure:   sc.secure,
		HttpOnly: true,
		SameSite: sc.sameSite,
		Expires:  time.Now().Add(time.Duration(maxAge) * time.Second),
	}, nil
}

// Decode opens the cookie value and returns the unmarshaled value.
func (sc *SecureCookieAEAD) Decode(cookie *http.Cookie, v any) error {
	if cookie == nil {
		return ErrCookieFormat
	}
	if sc.Codec == nil || sc.unmarshal == nil {
		return ErrCookieConfig
	}

	plainBytes, err := sc.Codec.Decode(cookie.Value, sc.aad())
	if err != nil {
		return err
	}

	if err := sc.unmarshal(plainBytes, v); err != nil {
		return err
	}
	return nil
}

// Clear returns a cookie that clears this cookie in the client.
func (sc *SecureCookieAEAD) Clear() *http.Cookie {
	if sc == nil {
		return nil
	}
	return &http.Cookie{
		Name:     sc.name,
		Domain:   sc.domain,
		Path:     sc.path,
		HttpOnly: true,
		Secure:   sc.secure,
		SameSite: sc.sameSite,
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
}
