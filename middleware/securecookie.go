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
type SecureCookie[T any] interface {
	// Name returns the cookie name used by this codec.
	Name() string
	Encode(plain T, maxAge int) (*http.Cookie, error)
	Decode(cookie *http.Cookie) (T, error)
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
		newAEAD = chacha20poly1305.NewX
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
type SecureCookieAEAD[T any] struct {
	CookieName string

	Codec *SecureCookieCodec

	// Default http.Cookie fields for encoded cookies.
	cfg secureCookieConfig

	// Marshal converts a value of type T to a byte slice for sealing.
	// If nil, defaults to cbor.Marshal from fxamacker/cbor/v2.
	Marshal func(any) ([]byte, error)

	// Unmarshal converts a byte slice into a value of type T.
	// If nil, defaults to cbor.Unmarshal from fxamacker/cbor/v2.
	Unmarshal func([]byte, any) error
}

// Name returns the cookie name.
func (sc *SecureCookieAEAD[T]) Name() string {
	if sc == nil {
		return ""
	}
	return sc.CookieName
}

// SecureCookieOption configures the SessionProcessor.
type SecureCookieOption func(*secureCookieConfig)

type secureCookieConfig struct {
	newAEAD  func([]byte) (cipher.AEAD, error)
	path     string
	domain   string
	secure   bool
	sameSite http.SameSite
}

// WithPath configures the cookie path.
func WithPath(path string) SecureCookieOption {
	return func(c *secureCookieConfig) {
		c.path = path
	}
}

// WithDomain configures the cookie domain.
func WithDomain(domain string) SecureCookieOption {
	return func(c *secureCookieConfig) {
		c.domain = domain
	}
}

// WithSecure configures the cookie secure flag.
func WithSecure(secure bool) SecureCookieOption {
	return func(c *secureCookieConfig) {
		c.secure = secure
	}
}

// WithSameSite configures the cookie sameSite attribute.
func WithSameSite(sameSite http.SameSite) SecureCookieOption {
	return func(c *secureCookieConfig) {
		c.sameSite = sameSite
	}
}

// WithAEAD configures the session to use a custom AEAD factory (e.g. AES-GCM).
func WithAEAD(f func([]byte) (cipher.AEAD, error)) SecureCookieOption {
	return func(c *secureCookieConfig) {
		c.newAEAD = f
	}
}

// NewCustomSecureCookie creates a SecureCookie codec with custom marshal/unmarshal.
func NewCustomSecureCookie[T any](cookieName string, keyID string, keys map[string][]byte, marshal func(any) ([]byte, error), unmarshal func([]byte, any) error, opts ...SecureCookieOption) (*SecureCookieAEAD[T], error) {
	cfg := secureCookieConfig{
		newAEAD:  nil, // Default AEAD (ChaCha20-Poly1305)
		domain:   "",
		path:     "/",
		secure:   true,
		sameSite: http.SameSiteLaxMode,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	codec, err := NewSecureCookieCodec(keyID, keys, cfg.newAEAD)
	if err != nil {
		return nil, err
	}

	if cfg.path == "" {
		cfg.path = "/"
	}

	// If marshal or unmarshal are not provided, default to CBOR encoding.
	if marshal == nil {
		marshal = cbor.Marshal
	}
	if unmarshal == nil {
		unmarshal = cbor.Unmarshal
	}

	return &SecureCookieAEAD[T]{
		CookieName: cookieName,
		Codec:      codec,
		cfg:        cfg,
		Marshal:    marshal,
		Unmarshal:  unmarshal,
	}, nil
}

func (sc *SecureCookieAEAD[T]) aad() []byte {
	secureStr := "f"
	if sc.cfg.secure {
		secureStr = "t"
	}
	return []byte(sc.CookieName + ":" + sc.cfg.domain + ":" + sc.cfg.path + ":" + secureStr)
}

// Encode marshals and seals plain and returns an http.Cookie carrying the value.
func (sc *SecureCookieAEAD[T]) Encode(plain T, maxAge int) (*http.Cookie, error) {
	if maxAge <= 0 {
		return nil, ErrCookieInvalid
	}
	if sc.Codec == nil || sc.Marshal == nil {
		return nil, ErrCookieConfig
	}

	plainBytes, err := sc.Marshal(plain)
	if err != nil {
		return nil, err
	}

	val, err := sc.Codec.Encode(plainBytes, sc.aad())
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     sc.CookieName,
		Value:    val,
		Path:     sc.cfg.path,
		Domain:   sc.cfg.domain,
		MaxAge:   maxAge,
		Secure:   sc.cfg.secure,
		HttpOnly: true,
		SameSite: sc.cfg.sameSite,
		Expires:  time.Now().Add(time.Duration(maxAge) * time.Second),
	}, nil
}

// Decode opens the cookie value and returns the unmarshaled value.
func (sc *SecureCookieAEAD[T]) Decode(cookie *http.Cookie) (T, error) {
	var zero T
	if cookie == nil {
		return zero, ErrCookieFormat
	}
	if sc.Codec == nil || sc.Unmarshal == nil {
		return zero, ErrCookieConfig
	}

	plainBytes, err := sc.Codec.Decode(cookie.Value, sc.aad())
	if err != nil {
		return zero, err
	}

	var plain T
	if err := sc.Unmarshal(plainBytes, &plain); err != nil {
		return zero, err
	}
	return plain, nil
}

// Clear returns a cookie that clears this cookie in the client.
func (sc *SecureCookieAEAD[T]) Clear() *http.Cookie {
	if sc == nil {
		return nil
	}
	return &http.Cookie{
		Name:     sc.CookieName,
		Domain:   sc.cfg.domain,
		Path:     sc.cfg.path,
		HttpOnly: true,
		Secure:   sc.cfg.secure,
		SameSite: sc.cfg.sameSite,
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
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
func NewSecureCookie[T any](cookieName, keyID string, keys map[string][]byte, opts ...SecureCookieOption) (SecureCookie[T], error) {
	return NewCustomSecureCookie[T](
		cookieName,
		keyID,
		keys,
		nil, // Default Marshal (CBOR)
		nil, // Default Unmarshal (CBOR)
		opts...,
	)
}
