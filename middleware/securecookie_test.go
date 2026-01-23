package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func newAESGCMAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type testPayload struct {
	Msg string
	Num int
}

func TestSecureCookieAEAD_RoundTrip(t *testing.T) {
	keys := map[string][]byte{
		"a": make([]byte, DefaultAEADKeysize),
	}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	sc, err := NewSecureCookie[testPayload]("sc", "a", keys,
		WithPath("/"), WithDomain("example.com"), WithSecure(false), WithSameSite(http.SameSiteNoneMode))
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD: %v", err)
	}

	plaintext := testPayload{Msg: "hello world", Num: 1}
	ck, err := sc.Encode(plaintext, 3600)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if ck == nil {
		t.Fatalf("Encode returned nil cookie")
	}
	if ck.Name != "sc" {
		t.Fatalf("cookie name: got %q want %q", ck.Name, "sc")
	}
	// Validate cookie attributes.
	if ck.Domain != "example.com" {
		t.Fatalf("cookie domain: got %q want %q", ck.Domain, "example.com")
	}
	if ck.Path != "/" {
		t.Fatalf("cookie path: got %q want %q", ck.Path, "/")
	}
	if !ck.HttpOnly {
		t.Fatalf("cookie HttpOnly: got %v want %v", ck.HttpOnly, true)
	}
	if ck.SameSite != http.SameSiteNoneMode {
		t.Fatalf("cookie SameSite: got %v want %v", ck.SameSite, http.SameSiteNoneMode)
	}
	if ck.Secure {
		t.Fatalf("cookie Secure: got %v want %v", ck.Secure, false)
	}
	if ck.Value == "" {
		t.Fatalf("cookie value empty")
	}

	got, err := sc.Decode(ck)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %+v want %+v", got, plaintext)
	}
}

func TestSecureCookieAEAD_Encode_UsesCurrentKeyID(t *testing.T) {
	keys := map[string][]byte{
		"a": make([]byte, DefaultAEADKeysize),
		"b": make([]byte, DefaultAEADKeysize),
	}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(a): %v", err)
	}
	if _, err := rand.Read(keys["b"]); err != nil {
		t.Fatalf("rand.Read(b): %v", err)
	}

	sc, err := NewSecureCookie[testPayload]("sc", "b", keys)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD: %v", err)
	}

	ck, err := sc.Encode(testPayload{Msg: "k", Num: 1}, 3600)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if ck == nil {
		t.Fatalf("Encode returned nil cookie")
	}
	if havePrefix, wantPrefix := strings.HasPrefix(ck.Value, "b."), true; havePrefix != wantPrefix {
		t.Fatalf("cookie value prefix: got %q want to start with %q", ck.Value, "b.")
	}
}

func TestSecureCookieAEAD_Clear_SetsCookieAttributes(t *testing.T) {
	keys := map[string][]byte{"a": make([]byte, DefaultAEADKeysize)}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	sc, err := NewSecureCookie[testPayload]("sc", "a", keys)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD: %v", err)
	}

	ck := sc.Clear()
	if ck == nil {
		t.Fatalf("Clear returned nil cookie")
	}
	if ck.Name != "sc" {
		t.Fatalf("cookie name: got %q want %q", ck.Name, "sc")
	}
	if ck.Value != "" {
		t.Fatalf("cookie value: got %q want empty", ck.Value)
	}
	if ck.MaxAge != -1 {
		t.Fatalf("cookie MaxAge: got %d want -1", ck.MaxAge)
	}
	if ck.Expires.IsZero() {
		t.Fatalf("cookie Expires: expected non-zero")
	}
}

func TestSecureCookieAEAD_Decode_NilCookie_IsFormatError(t *testing.T) {
	keys := map[string][]byte{"a": make([]byte, DefaultAEADKeysize)}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}
	sc, err := NewSecureCookie[testPayload]("sc", "a", keys)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD: %v", err)
	}
	if _, err := sc.Decode(nil); err != ErrCookieFormat {
		t.Fatalf("Decode(nil): got %v want %v", err, ErrCookieFormat)
	}
}

func TestSecureCookieAEAD_Decode_UnknownKeyID_IsInvalid(t *testing.T) {
	keys := map[string][]byte{"a": make([]byte, DefaultAEADKeysize)}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}
	sc, err := NewSecureCookie[testPayload]("sc", "a", keys)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD: %v", err)
	}
	if _, err := sc.Decode(&http.Cookie{Name: "sc", Value: "nope.deadbeef"}); err != ErrCookieInvalid {
		t.Fatalf("Decode(unknown keyID): got %v want %v", err, ErrCookieInvalid)
	}
}

func TestSecureCookieAEAD_Rotation_OldKeyStillDecodes(t *testing.T) {
	keys := map[string][]byte{
		"old": make([]byte, DefaultAEADKeysize),
		"new": make([]byte, DefaultAEADKeysize),
	}
	if _, err := rand.Read(keys["old"]); err != nil {
		t.Fatalf("rand.Read(old): %v", err)
	}
	if _, err := rand.Read(keys["new"]); err != nil {
		t.Fatalf("rand.Read(new): %v", err)
	}

	scOld, err := NewSecureCookie[testPayload]("sc", "old", keys)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD(old): %v", err)
	}
	scNew, err := NewSecureCookie[testPayload]("sc", "new", keys)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD(new): %v", err)
	}

	plaintext := testPayload{Msg: "rotate", Num: 2}
	ck, err := scOld.Encode(plaintext, 3600)
	if err != nil {
		t.Fatalf("Encode(old): %v", err)
	}

	got, err := scNew.Decode(ck)
	if err != nil {
		t.Fatalf("Decode(with new instance): %v", err)
	}
	if !reflect.DeepEqual(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %+v want %+v", got, plaintext)
	}
}

func TestSecureCookieAEAD_TamperRejected(t *testing.T) {
	keys := map[string][]byte{
		"a": make([]byte, DefaultAEADKeysize),
	}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	sc, err := NewSecureCookie[testPayload]("sc", "a", keys)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD: %v", err)
	}

	ck, err := sc.Encode(testPayload{Msg: "secret", Num: 3}, 3600)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Flip a bit in the cookie value.
	v := []byte(ck.Value)
	// Last two characters may be base64 padding, so flip third-last.
	v[len(v)-3] ^= 0x01
	ck2 := &http.Cookie{Name: ck.Name, Value: string(v), Domain: ck.Domain, Path: ck.Path}

	if _, err := sc.Decode(ck2); err == nil {
		t.Fatalf("Decode(tampered): expected error")
	} else if err != ErrCookieInvalid && err != ErrCookieFormat {
		// Depending on the flip location it might become invalid base64.
		t.Fatalf("Decode(tampered): got %v want %v or %v", err, ErrCookieInvalid, ErrCookieFormat)
	}
}

func TestSecureCookieAEAD_AADMismatchRejected(t *testing.T) {
	keys := map[string][]byte{
		"a": make([]byte, DefaultAEADKeysize),
	}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	sc1, err := NewSecureCookie[testPayload]("sc", "a", keys,
		WithPath("/"), WithDomain("example.com"), WithSecure(false), WithSameSite(http.SameSiteLaxMode))
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD(sc1): %v", err)
	}
	sc2, err := NewSecureCookie[testPayload]("sc", "a", keys,
		WithPath("/"), WithDomain("other.com"), WithSecure(false), WithSameSite(http.SameSiteLaxMode))
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD(sc2): %v", err)
	}

	ck, err := sc1.Encode(testPayload{Msg: "secret", Num: 4}, 3600)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := sc2.Decode(ck); err != ErrCookieInvalid {
		t.Fatalf("Decode(AAD mismatch): got %v want %v", err, ErrCookieInvalid)
	}
}

func TestNewSecureCookieAEAD_Validation(t *testing.T) {
	key := make([]byte, DefaultAEADKeysize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	if _, err := NewSecureCookie[testPayload]("sc", "missing", map[string][]byte{"a": key}); err == nil {
		t.Fatalf("expected error for missing keyID")
	}

	if _, err := NewSecureCookie[testPayload]("sc", "a", nil); err == nil {
		t.Fatalf("expected error for nil keys")
	}

	badKeys := map[string][]byte{"a": key, "b": make([]byte, DefaultAEADKeysize-1)}
	if _, err := NewSecureCookie[testPayload]("sc", "a", badKeys); err == nil {
		t.Fatalf("expected error for inconsistent key lengths")
	}
}

func TestSecureCookieAEAD_NilNewAEAD_IsConfigError(t *testing.T) {
	key := make([]byte, DefaultAEADKeysize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	// Deliberately bypass constructor to ensure methods don't panic.
	sc := &SecureCookieAEAD[testPayload]{CookieName: "sc"}
	if _, err := sc.Encode(testPayload{Msg: "x", Num: 5}, 3600); err != ErrCookieConfig {
		t.Fatalf("Encode: got %v want %v", err, ErrCookieConfig)
	}
	if _, err := sc.Decode(&http.Cookie{Name: "sc", Value: "a.deadbeef"}); err != ErrCookieConfig {
		t.Fatalf("Decode: got %v want %v", err, ErrCookieConfig)
	}
}

func TestSecureCookieAEAD_CustomMarshal(t *testing.T) {
	keys := map[string][]byte{"a": make([]byte, DefaultAEADKeysize)}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	sc, err := NewCustomSecureCookie[testPayload]("sc", "a", keys, json.Marshal, json.Unmarshal)
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD(custom): %v", err)
	}

	in := testPayload{Msg: "custom", Num: 42}
	ck, err := sc.Encode(in, 3600)
	if err != nil {
		t.Fatalf("Encode(custom): %v", err)
	}
	got, err := sc.Decode(ck)
	if err != nil {
		t.Fatalf("Decode(custom): %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("custom mismatch: got %+v want %+v", got, in)
	}
}

func TestSecureCookieAEAD_CustomAEAD_AESGCM(t *testing.T) {
	keys := map[string][]byte{"a": make([]byte, 32)}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	sc, err := NewCustomSecureCookie[testPayload]("sc", "a", keys, json.Marshal, json.Unmarshal, WithAEAD(newAESGCMAEAD))
	if err != nil {
		t.Fatalf("NewSecureCookieAEAD(custom AEAD): %v", err)
	}

	in := testPayload{Msg: "aead", Num: 7}
	ck, err := sc.Encode(in, 3600)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := sc.Decode(ck)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip: got %+v want %+v", got, in)
	}

	// Tamper with cookie value; should fail integrity.
	v := []byte(ck.Value)
	// Last two characters may be base64 padding, so flip third-last.
	v[len(v)-3] ^= 0x01
	ck2 := &http.Cookie{Name: ck.Name, Value: string(v), Domain: ck.Domain, Path: ck.Path}
	if _, err := sc.Decode(ck2); err == nil {
		t.Fatalf("Decode(tampered): expected error")
	}
}
