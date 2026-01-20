package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/mnehpets/oneserve/endpoint"
	"github.com/mnehpets/oneserve/middleware"
	"golang.org/x/oauth2"
)

func TestAuthHandler_Login(t *testing.T) {
	// Setup keys and state manager
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()

	// Setup fake provider endpoint
	// Setup fake provider endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock Token Endpoint
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "mock_access_token", "token_type": "Bearer", "expires_in": 3600}`))
			return
		}
		// Mock Auth Endpoint (just for URL construction check)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conf := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
		},
		Scopes: []string{"openid"},
	}
	reg.RegisterOAuth2Provider("test-provider", conf)

	// Create Handler
	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// 1. Test Login Redirect
	w := httptest.NewRecorder()
	// Base64url encode app_data since it's now expected to be base64url encoded
	appDataValue := base64.RawURLEncoding.EncodeToString([]byte("123"))
	r := httptest.NewRequest("GET", "/auth/login/test-provider?next=/dashboard&app_data="+appDataValue, nil)
	h.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, srv.URL+"/auth") {
		t.Errorf("expected redirect to provider auth, got %s", loc)
	}
	if !strings.Contains(loc, "state=") {
		t.Error("expected state param")
	}

	// Capture cookie for callback
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no state cookie set")
	}

	// Extract state from location
	// Location: .../auth?client_id=...&state=XXX&...
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")

	// 2. Test Callback
	// Mock success hook
	var successCalled bool
	h.success = func(w http.ResponseWriter, r *http.Request, params *SuccessParams) (endpoint.Renderer, error) {
		successCalled = true
		if params.ProviderID != "test-provider" {
			t.Errorf("expected provider test-provider, got %s", params.ProviderID)
		}
		if string(params.AppData) != "123" {
			t.Errorf("expected app_data 123, got %s", string(params.AppData))
		}
		if params.Token.AccessToken != "mock_access_token" {
			t.Errorf("expected access token mock_access_token, got %s", params.Token.AccessToken)
		}
		return &endpoint.RedirectRenderer{URL: "/dashboard", Status: http.StatusFound}, nil
	}

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/test-provider?code=mock_code&state="+state, nil)
	r2.AddCookie(cookies[0]) // Add state cookie
	h.ServeHTTP(w2, r2)

	if w2.Result().StatusCode != http.StatusFound {
		t.Errorf("callback failed: %v", w2.Result().Status)
	}
	if !successCalled {
		t.Error("success hook not called")
	}
}

func TestAuthHandler_OpenRedirect(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider", TokenURL: "http://provider"}})

	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// Attempt open redirect
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test?next_url=//evil.com", nil)
	h.ServeHTTP(w, r)

	// Check cookie state
	c := w.Result().Cookies()[0]
	states, _ := cookie.Decode(c)
	// Iterate to find the single state
	for _, s := range states {
		if s.AuthParams.NextURL != "/" {
			t.Errorf("expected NextURL to be '/', got %q", s.AuthParams.NextURL)
		}
	}
}

func TestAuthHandler_Callback_Errors(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{}) // Register dummy provider
	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// 1. Provider Error
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/test?error=access_denied&error_description=user_denied", nil)
	h.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for provider error, got %d", w.Result().StatusCode)
	}

	// 2. Invalid State (missing cookie)
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/test?state=missing", nil)
	h.ServeHTTP(w2, r2)
	if w2.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid state, got %d", w2.Result().StatusCode)
	}
}

func TestAuthHandler_StateEviction(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider"}})

	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// Initiate 4 logins
	var cookies []*http.Cookie
	lastCookie := &http.Cookie{}

	for i := 0; i < 4; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/login/test", nil)
		if i > 0 {
			r.AddCookie(lastCookie)
		}
		h.ServeHTTP(w, r)
		lastCookie = w.Result().Cookies()[0]
		cookies = append(cookies, lastCookie)
	}

	// Decode final cookie
	states, _ := cookie.Decode(lastCookie)
	if len(states) != 3 {
		t.Errorf("expected 3 states (max), got %d", len(states))
	}
}

func TestAuthHandler_StateExpiry(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})
	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// Manually create expired state in cookie
	expiredState := AuthState{
		AuthParams: AuthParams{NextURL: "/"},
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}
	states := AuthStateMap{"expired_state": expiredState}
	c, _ := cookie.Encode(states, 3600)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/test?state=expired_state&code=123", nil)
	r.AddCookie(c)

	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for expired state, got %d", w.Result().StatusCode)
	}
}

func TestAuthHandler_OIDCNonceMismatch(t *testing.T) {
	// 1. Setup Mock OIDC Server
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, (&jose.SignerOptions{}).WithType("JWT"))

	var oidcServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := oidcServer.URL
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                issuer,
				"jwks_uri":                              issuer + "/keys",
				"authorization_endpoint":                issuer + "/auth",
				"token_endpoint":                        issuer + "/token",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
			return
		}
		if r.URL.Path == "/keys" {
			jwk := jose.JSONWebKey{Key: &privKey.PublicKey, Use: "sig", Algorithm: "RS256", KeyID: "test-key"}
			jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
			json.NewEncoder(w).Encode(jwks)
			return
		}
		if r.URL.Path == "/token" {
			// Return ID Token with WRONG nonce
			claims := jwt.Claims{
				Subject:   "user123",
				Issuer:    issuer,
				Audience:  jwt.Audience{"client-id"},
				Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			}
			// Add nonce
			rawJWT, _ := jwt.Signed(signer).Claims(claims).Claims(map[string]interface{}{"nonce": "WRONG_NONCE"}).Serialize()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "token",
				"id_token":     rawJWT,
				"token_type":   "Bearer",
			})
			return
		}
	})
	oidcServer = httptest.NewServer(handler)
	defer oidcServer.Close()

	ctx := context.Background()
	reg := NewRegistry()
	err := reg.RegisterOIDCProvider(ctx, "oidc-test", oidcServer.URL, "client-id", "secret", []string{"openid"}, "http://example.com/callback")
	if err != nil {
		t.Fatalf("failed to register OIDC provider: %v", err)
	}

	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// 1. Setup Cookie with expected nonce
	expectedNonce := "EXPECTED_NONCE"
	state := "state123"
	authState := AuthState{
		AuthParams: AuthParams{NextURL: "/"},
		Nonce:      expectedNonce,
	}
	c, _ := cookie.Encode(AuthStateMap{state: authState}, 3600)

	// 2. Call Callback
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/oidc-test?state="+state+"&code=foo", nil)
	r.AddCookie(c)

	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for nonce mismatch, got %d", w.Result().StatusCode)
	}
	body := w.Body.String()
	if !strings.Contains(body, "nonce mismatch") {
		t.Errorf("expected 'nonce mismatch' error, got %s", body)
	}
}

func TestAuthHandler_PreAuthFailure(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})

	// Pre-auth hook that fails
	failPreAuth := func(ctx context.Context, w http.ResponseWriter, r *http.Request, pid string, params AuthParams) (AuthParams, error) {
		return params, endpoint.Error(http.StatusForbidden, "blocked by pre-auth", nil)
	}

	h := NewHandler(reg, cookie, "http://example.com", "/auth", WithPreAuthHook(failPreAuth))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test", nil)
	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestAuthHandler_SuccessHookFailure(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()

	// Mock Provider
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "token", "token_type": "Bearer"}`))
			return
		}
	}))
	defer srv.Close()

	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token"}})

	// Success endpoint that fails
	successEndpoint := func(w http.ResponseWriter, r *http.Request, params *SuccessParams) (endpoint.Renderer, error) {
		return nil, endpoint.Error(http.StatusTeapot, "simulated failure", nil)
	}

	h := NewHandler(reg, cookie, "http://example.com", "/auth", WithSuccessEndpoint(successEndpoint))

	// Setup valid state
	state := "state123"
	authState := AuthState{
		AuthParams: AuthParams{NextURL: "/"},
	}
	c, _ := cookie.Encode(AuthStateMap{state: authState}, 3600)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/test?state="+state+"&code=foo", nil)
	r.AddCookie(c)

	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusTeapot {
		t.Errorf("expected 418, got %d", w.Result().StatusCode)
	}
}

func TestAuthHandler_PKCEGeneration(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	// PKCE enabled by default in RegisterOAuth2Provider
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth"}})

	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test", nil)
	h.ServeHTTP(w, r)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "code_challenge=") {
		t.Error("expected code_challenge in auth URL")
	}
	if !strings.Contains(loc, "code_challenge_method=S256") {
		t.Error("expected S256 challenge method")
	}

	// Verify Verifier is stored in cookie
	c := w.Result().Cookies()[0]
	states, _ := cookie.Decode(c)
	for _, s := range states {
		if s.PKCEVerifier == "" {
			t.Error("expected PKCE verifier stored in state")
		}
	}
}

func TestAuthHandler_CookieSecurity(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	// We need to verify that NewHandler doesn't override secure settings passed to it,
	// but here we are passing the cookie *instance* to NewHandler.
	// So we test that the cookie instance *we create* behaves as expected when used by Handler.

	// Actually, StateManager (internal) used to handle this. Now Handler calls h.cookie.Encode().
	// So the security depends on how we initialized the cookie passed to NewHandler.
	// Let's verify that the handler *uses* the cookie correctly.

	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys,
		middleware.WithCookieOptions("/", "example.com", true, true, http.SameSiteLaxMode))

	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})
	h := NewHandler(reg, cookie, "https://example.com", "/auth")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test", nil)
	h.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies")
	}
	c := cookies[0]

	if !c.Secure {
		t.Error("expected Secure cookie")
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly cookie")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("expected SameSite=Lax")
	}
}

func TestAuthHandler_UnknownProvider(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// 1. Login with unknown provider
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/unknown", nil)
	h.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("login: expected 404 for unknown provider, got %d", w.Result().StatusCode)
	}

	// 2. Callback with unknown provider
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/unknown?state=foo&code=bar", nil)
	h.ServeHTTP(w2, r2)
	// Note: It might fail validation before provider check if we're not careful,
	// but provider check should happen early.
	// Actually, looking at handler.go:
	// handleCallback checks Error param first, then Provider existence.
	if w2.Result().StatusCode != http.StatusNotFound {
		t.Errorf("callback: expected 404 for unknown provider, got %d", w2.Result().StatusCode)
	}
}

func TestAuthHandler_AppDataPersistence(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "token", "token_type": "Bearer"}`))
	}))
	defer srv.Close()

	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: srv.URL}})

	var capturedAppData []byte
	h := NewHandler(reg, cookie, "http://example.com", "/auth", WithSuccessEndpoint(func(w http.ResponseWriter, r *http.Request, params *SuccessParams) (endpoint.Renderer, error) {
		capturedAppData = params.AppData
		return &endpoint.RedirectRenderer{URL: "/"}, nil
	}))

	// Complex app data
	complexData := "user_id=123&role=admin with spaces/and/slashes"

	// 1. Login
	w := httptest.NewRecorder()
	// Base64url encode the app_data in the query since it's now expected to be base64url encoded
	u := url.Values{}
	u.Set("app_data", base64.RawURLEncoding.EncodeToString([]byte(complexData)))
	r := httptest.NewRequest("GET", "/auth/login/test?"+u.Encode(), nil)
	h.ServeHTTP(w, r)

	// Extract state
	c := w.Result().Cookies()[0]
	loc := w.Result().Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	// 2. Callback
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/test?code=foo&state="+state, nil)
	r2.AddCookie(c)
	h.ServeHTTP(w2, r2)

	if string(capturedAppData) != complexData {
		t.Errorf("AppData mismatch.\nExpected: %q\nGot:      %q", complexData, string(capturedAppData))
	}
}

func TestAuthHandler_PKCE_Disabled(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()

	conf := &oauth2.Config{
		Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth", TokenURL: "http://provider/token"},
	}
	p := NewProvider("no-pkce", conf, nil, nil)
	p.SetPKCE(false)
	reg.Register(p)

	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/no-pkce", nil)
	h.ServeHTTP(w, r)

	loc := w.Result().Header.Get("Location")
	if strings.Contains(loc, "code_challenge") {
		t.Error("expected no code_challenge when PKCE is disabled")
	}
}

func TestAuthHandler_AppDataMaxLength(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie[AuthStateMap]("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth"}})

	h := NewHandler(reg, cookie, "http://example.com", "/auth")

	// Test with exactly 512 bytes - should pass
	okData := make([]byte, 512)
	for i := range okData {
		okData[i] = 'A'
	}
	okEncoded := base64.RawURLEncoding.EncodeToString(okData)

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/auth/login/test?app_data="+okEncoded, nil)
	h.ServeHTTP(w1, r1)

	if w1.Result().StatusCode != http.StatusFound {
		t.Errorf("expected 302 for 512 bytes, got %d: %s", w1.Result().StatusCode, w1.Body.String())
	}

	// Test with 513 bytes - should fail due to exceeding 512-byte limit
	// Note: 513 bytes encodes to 684 chars, which exceeds maxLength of 683
	// So this will fail at the decoder level with a generic "Bad Request" error
	longData := make([]byte, 513)
	for i := range longData {
		longData[i] = 'A'
	}
	longEncoded := base64.RawURLEncoding.EncodeToString(longData)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/login/test?app_data="+longEncoded, nil)
	h.ServeHTTP(w2, r2)

	// Should fail because it exceeds 512 bytes (fails at decoder or handler level)
	if w2.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for 513 bytes, got %d", w2.Result().StatusCode)
	}
}

