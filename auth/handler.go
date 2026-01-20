package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mnehpets/oneserve/endpoint"
	"github.com/mnehpets/oneserve/middleware"
	"golang.org/x/oauth2"
)

// PreAuthHook is an optional hook invoked before the flow starts.
type PreAuthHook func(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID string, params AuthParams) (AuthParams, error)

// AuthParams contains parameters for initiating an OAuth flow.
// It is used for both LoginParams and AuthState to ensure consistency.
type AuthParams struct {
	NextURL string `query:"next_url" cbor:"1,keyasint,omitempty"`
	AppData []byte `query:"app_data,base64url" cbor:"2,keyasint,omitempty" maxLength:"700"`
}

type SuccessParams struct {
	ProviderID string
	Token      *oauth2.Token
	IDToken    *oidc.IDToken
	AppData    []byte
	NextURL    string
}

// SuccessEndpoint is invoked after a successful OAuth callback.
type SuccessEndpoint endpoint.EndpointFunc[*SuccessParams]

// FailureEndpoint is invoked when an OAuth flow fails.
// It has the requirements of an endpoint.EndpointFunc.
// It should return a Renderer to render the failure response.
// If it returns an error, the error will be handled by the default error handling mechanism.
type FailureEndpoint endpoint.EndpointFunc[error]

// defaultPreAuthHook is the default implementation.
// It ensures the NextURL is a safe relative path to prevent open redirects.
func defaultPreAuthHook(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID string, params AuthParams) (AuthParams, error) {
	params.NextURL = ValidateNextURLIsLocal(params.NextURL)
	return params, nil
}

// defaultSuccessEndpoint is the default implementation that redirects to NextURL.
func defaultSuccessEndpoint(w http.ResponseWriter, r *http.Request, params *SuccessParams) (endpoint.Renderer, error) {
	return &endpoint.RedirectRenderer{URL: params.NextURL, Status: http.StatusFound}, nil
}

// defaultFailureEndpoint is the default implementation that simply returns the error.
func defaultFailureEndpoint(w http.ResponseWriter, r *http.Request, err error) (endpoint.Renderer, error) {
	return nil, err
}

// AuthHandler implements the OAuth flow orchestration.
type AuthHandler struct {
	mux       *http.ServeMux
	registry  *Registry
	publicURL string
	basePath  string

	// State Management
	cookie middleware.SecureCookie[AuthStateMap]

	preAuth PreAuthHook
	success SuccessEndpoint
	failure FailureEndpoint

	// processors are the middleware processors to run for each endpoint
	processors []endpoint.Processor
}

// Option configures the AuthHandler.
type Option func(*AuthHandler)

// WithProcessors adds middleware processors to the auth endpoints.
func WithProcessors(p ...endpoint.Processor) Option {
	return func(ah *AuthHandler) {
		ah.processors = append(ah.processors, p...)
	}
}

// WithPreAuthHook sets the PreAuthHook.
func WithPreAuthHook(h PreAuthHook) Option {
	return func(ah *AuthHandler) {
		ah.preAuth = h
	}
}

// WithSuccessEndpoint sets the SuccessEndpoint.
func WithSuccessEndpoint(h SuccessEndpoint) Option {
	return func(ah *AuthHandler) {
		ah.success = h
	}
}

// WithFailureEndpoint sets the FailureEndpoint.
func WithFailureEndpoint(h FailureEndpoint) Option {
	return func(ah *AuthHandler) {
		ah.failure = h
	}
}

// maxStates is the maximum number of concurrent auth states per user-agent.
// This prevents cookie bloat and limits the potential for state replay attacks.
const maxStates = 3

// authStateTTL is the duration for which an auth state is valid.
const authStateTTL = time.Hour

// NewHandler creates a new AuthHandler.
// publicURL should be the base public URL of the application (e.g., "https://example.com").
// basePath is the path where this handler is mounted (e.g., "/auth").
func NewHandler(registry *Registry, cookie middleware.SecureCookie[AuthStateMap], publicURL, basePath string, opts ...Option) *AuthHandler {
	h := &AuthHandler{
		mux:       http.NewServeMux(),
		registry:  registry,
		cookie:    cookie,
		publicURL: strings.TrimRight(publicURL, "/"),
		basePath:  basePath,
		preAuth:   defaultPreAuthHook,
		success:   defaultSuccessEndpoint,
		failure:   defaultFailureEndpoint,
	}
	for _, opt := range opts {
		opt(h)
	}

	// Ensure leading slash for basePath
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	// Endpoint for /prefix/login/{provider}
	h.mux.HandleFunc("GET "+path.Join(basePath, "login", "{provider}"), endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, params LoginParams) (endpoint.Renderer, error) {
		ctx := r.Context()
		providerID := params.ProviderID

		p, ok := h.registry.Get(providerID)
		if !ok {
			return nil, endpoint.Error(http.StatusNotFound, "provider not found", nil)
		}

		// 1. PreAuth Hook
		var err error
		// preAuth sanitizes and returns updated AuthParams
		params.AuthParams, err = h.preAuth(ctx, w, r, providerID, params.AuthParams)
		if err != nil {
			return h.failure(w, r, endpoint.Error(http.StatusBadRequest, "pre-auth failed", err))
		}

		// Check AppData length (decoded)
		if len(params.AuthParams.AppData) > 512 {
			return h.failure(w, r, endpoint.Error(http.StatusBadRequest, "app_data exceeds maximum length of 512 bytes", nil))
		}

		// 2. Prepare State
		state, err := generateState()
		if err != nil {
			return h.failure(w, r, endpoint.Error(http.StatusInternalServerError, "failed to generate state", err))
		}

		authState := AuthState{
			AuthParams: params.AuthParams,
		}

		// 3. PKCE
		var codeChallenge string
		if p.usePKCE {
			verifier, challenge, err := generatePKCE()
			if err != nil {
				return h.failure(w, r, endpoint.Error(http.StatusInternalServerError, "failed to generate PKCE", err))
			}
			authState.PKCEVerifier = verifier
			codeChallenge = challenge
		}

		// 4. OIDC Nonce
		var nonce string
		if p.oidcProvider != nil {
			nonce, err = generateState() // Reuse random string gen
			if err != nil {
				return h.failure(w, r, endpoint.Error(http.StatusInternalServerError, "failed to generate nonce", err))
			}
			authState.Nonce = nonce
		}

		// 5. Store State
		if err := h.addState(w, r, state, authState); err != nil {
			return h.failure(w, r, endpoint.Error(http.StatusInternalServerError, "failed to save state", err))
		}

		// 6. Redirect
		// Clone config to set RedirectURL
		conf := *p.config
		conf.RedirectURL = h.constructCallbackURL(providerID)

		opts := []oauth2.AuthCodeOption{}
		if p.usePKCE {
			opts = append(opts, oauth2.SetAuthURLParam("code_challenge", codeChallenge))
			opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
		}
		if nonce != "" {
			opts = append(opts, oidc.Nonce(nonce))
		}

		redirectURL := conf.AuthCodeURL(state, opts...)
		return &endpoint.RedirectRenderer{URL: redirectURL, Status: http.StatusFound}, nil
	}, h.processors...))

	h.mux.HandleFunc("GET "+path.Join(basePath, "callback", "{provider}"), endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, params CallbackParams) (endpoint.Renderer, error) {
		ctx := r.Context()
		providerID := params.ProviderID

		// Check for provider error
		if params.Error != "" {
			err := fmt.Errorf("provider error: %s (description: %s)", params.Error, params.ErrorDesc)
			return h.failure(w, r, endpoint.Error(http.StatusBadRequest, "provider returned error", err))
		}

		p, ok := h.registry.Get(providerID)
		if !ok {
			return nil, endpoint.Error(http.StatusNotFound, "provider not found", nil)
		}

		// Retrieve state
		authState, err := h.popState(w, r, params.State)
		if err != nil {
			return h.failure(w, r, endpoint.Error(http.StatusBadRequest, "invalid state", err))
		}

		// Prepare Exchange options
		opts := []oauth2.AuthCodeOption{}
		if authState.PKCEVerifier != "" {
			opts = append(opts, oauth2.SetAuthURLParam("code_verifier", authState.PKCEVerifier))
		}

		// Exchange code
		// Clone config to set RedirectURL (must match what was sent in login)
		conf := *p.config
		conf.RedirectURL = h.constructCallbackURL(providerID)

		token, err := conf.Exchange(ctx, params.Code, opts...)
		if err != nil {
			return h.failure(w, r, endpoint.Error(http.StatusInternalServerError, "token exchange failed", err))
		}

		// OIDC Validation
		var idToken *oidc.IDToken
		if p.oidcProvider != nil {
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				err := fmt.Errorf("no id_token returned")
				return h.failure(w, r, endpoint.Error(http.StatusInternalServerError, "no id_token returned", err))
			}

			verifier := p.verifier
			idToken, err = verifier.Verify(ctx, rawIDToken)
			if err != nil {
				return h.failure(w, r, endpoint.Error(http.StatusInternalServerError, "id_token verification failed", err))
			}

			// Verify Nonce
			if authState.Nonce != "" {
				if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(authState.Nonce)) != 1 {
					err := fmt.Errorf("nonce mismatch")
					return h.failure(w, r, endpoint.Error(http.StatusBadRequest, "nonce mismatch", err))
				}
			}
		}

		// Success
		successParams := SuccessParams{
			ProviderID: providerID,
			Token:      token,
			IDToken:    idToken,
			AppData:    authState.AuthParams.AppData,
			NextURL:    authState.AuthParams.NextURL,
		}
		return h.success(w, r, &successParams)
	}, h.processors...))

	return h
}

func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// Internal State Management Methods

func (h *AuthHandler) addState(w http.ResponseWriter, r *http.Request, state string, authState AuthState) error {
	// Read existing cookie
	c, _ := r.Cookie(h.cookie.Name())
	var states AuthStateMap
	var err error

	if c != nil {
		states, err = h.cookie.Decode(c)
		if err != nil {
			states = make(AuthStateMap)
		}
	} else {
		states = make(AuthStateMap)
	}

	// 1. Cleanup expired states
	now := time.Now()
	for k, v := range states {
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			delete(states, k)
		}
	}

	// 2. Evict if still full
	if len(states) >= maxStates {
		var oldestKey string
		var oldestTime time.Time

		for k, v := range states {
			if oldestKey == "" || v.ExpiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.ExpiresAt
			}
		}
		if oldestKey != "" {
			delete(states, oldestKey)
		}
	}

	// 3. Add new state
	authState.ExpiresAt = now.Add(authStateTTL)
	states[state] = authState

	// Encode and set cookie
	newCookie, err := h.cookie.Encode(states, int(authStateTTL.Seconds()))
	if err != nil {
		return err
	}
	http.SetCookie(w, newCookie)
	return nil
}

func (h *AuthHandler) popState(w http.ResponseWriter, r *http.Request, state string) (AuthState, error) {
	c, err := r.Cookie(h.cookie.Name())
	if err != nil {
		return AuthState{}, err
	}

	states, err := h.cookie.Decode(c)
	if err != nil {
		return AuthState{}, err
	}

	authState, ok := states[state]
	if !ok {
		return AuthState{}, errors.New("state not found")
	}

	// Check expiry
	if !authState.ExpiresAt.IsZero() && time.Now().After(authState.ExpiresAt) {
		// Even if found, it's expired. Remove it and fail.
		delete(states, state)
		// Update cookie (cleanup)
		h.updateCookie(w, states)
		return AuthState{}, errors.New("state expired")
	}

	// Remove the state
	delete(states, state)

	// Update the cookie
	if err := h.updateCookie(w, states); err != nil {
		return AuthState{}, err
	}

	return authState, nil
}

func (h *AuthHandler) updateCookie(w http.ResponseWriter, states AuthStateMap) error {
	if len(states) == 0 {
		http.SetCookie(w, h.cookie.Clear())
		return nil
	}
	newCookie, err := h.cookie.Encode(states, int(authStateTTL.Seconds()))
	if err != nil {
		return err
	}
	http.SetCookie(w, newCookie)
	return nil
}

func (h *AuthHandler) constructCallbackURL(providerID string) string {
	u, err := url.Parse(h.publicURL)
	if err != nil {
		// Fallback, though this shouldn't happen if publicURL is valid
		return h.publicURL + path.Join(h.basePath, "callback", providerID)
	}
	u.Path = path.Join(u.Path, h.basePath, "callback", providerID)
	return u.String()
}

type LoginParams struct {
	ProviderID string `path:"provider"`
	AuthParams
}

type CallbackParams struct {
	ProviderID string `path:"provider"`
	State      string `query:"state"`
	Code       string `query:"code"`
	Error      string `query:"error"`
	ErrorDesc  string `query:"error_description"`
}
