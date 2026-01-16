## Context
The project provides a type-safe HTTP endpoint pipeline (`endpoint`) and session middleware implemented with secure cookies (`middleware/session`). This change introduces a standardized OAuth callback handler that can coordinate OAuth flows across multiple providers and optionally process OIDC ID tokens.

## Goals
- Provide a reusable handler component that can be mounted in a net/http mux and/or wrapped via `endpoint.HandleFunc`.
- Support multiple providers concurrently (Microsoft, Google, others).
- Support multiple simultaneous OAuth flows per user-agent without collisions.
- Support OIDC ID token validation and identity extraction.

## Non-Goals
- Fully featured identity system.
- Persistent credential vaulting strategy.

## Proposed Architecture
### Auth root handler
Provide a single HTTP handler that can be mounted at an arbitrary base path (e.g. `/auth`, `/blah`). Internally it muxes sub-routes below that base path, such as:
- `/<base>/login/{provider}` (starts the OAuth flow; redirects to provider)
  - Accepts `next_url` and `app_data` via query parameters.
  - Supports an optional `PreAuthHandler` hook to programmatically validate/override these parameters before the flow starts.
- `/<base>/callback/{provider}` (OAuth/OIDC callback handling)

This keeps provider registration/configuration and cookie/state management centralized, while allowing applications to choose their URL layout by selecting the mount path.

### Provider registry
The implementation should leverage `golang.org/x/oauth2` for core OAuth mechanics and `github.com/coreos/go-oidc/v3/oidc` for ID token validation.
Define a registry keyed by provider ID (string) which supplies:
- `oauth2.Config` (containing Client ID, Secret, Endpoint, Scopes)
- token exchange logic (standard `Exchange` vs custom)
- optional ID token validation parameters (issuer, audience/client-id, JWKS)

#### Application configuration surface
Applications need a straightforward way to register providers and their configuration (client id/secret, callback base, scopes, etc) without hard-coding provider logic into the handler.

Proposed pattern:
- `AuthHandler` is created with one or more functional options.
- Providers are registered up-front into an internal registry keyed by provider id.
- **Public URL**: The handler MUST be configured with the application's public base URL (e.g., `https://myapp.com`) to correctly construct the `redirect_uri` sent to providers.

Suggested interfaces (illustrative; subject to revision during implementation):

- `type Provider interface { ID() string /* ... */ }`
- `type ProviderRegistry interface { Get(id string) (Provider, bool) }`

Practical option shape:
- `WithProvider(p Provider)` and/or `WithProviders(map[string]Provider)`.

The provider config should allow at minimum:
- which flows are supported (login, credentials, or both simultaneously)
- whether PKCE is enabled
- oauth2 endpoints + client credentials
- scopes
- optional OIDC parameters

### Flow correlation
The OAuth `state` parameter is an opaque identifier that can be passed in the OAuth `state` value. The handler uses this identifier as a lookup key into a `AuthStateMap` stored in a secure cookie.

The `AuthState` object is the authoritative representation of the in-flight OAuth/OIDC flow and may contain additional fields required for correctness and safety, including (non-exhaustive):
- OIDC `nonce` (replay prevention)
- `next_url` (post-callback redirect)
- `AppData` (opaque string passed during flow initiation; MUST be small, e.g. < 512 bytes)
- provider identifier and/or flow type metadata
- timestamps / expiry

The `AuthStateMap` is stored in a **dedicated** `AuthStateCookie` (separate from any session cookie) to decouple OAuth flow state from session behavior that may occur in parallel.

### Callback multiplexing
The callback route is exposed as `/<base>/callback/{provider}` (relative to the handler mount path).

### Security Architecture
The handler MUST enforce strict security controls:
1.  **PKCE (Proof Key for Code Exchange)**:
    - MUST be supported by the handler.
    - Application configuration determines if PKCE is enabled per provider.
    - If enabled: `code_challenge` (S256) sent in auth request; `code_verifier` sent in token exchange.
2.  **Strict OIDC Validation**:
    - If an ID Token is present, it MUST be validated (Signature, Issuer, Audience, Expiry, Nonce).
    - Best-effort/unverified parsing is NOT allowed for identity establishment.
3.  **State Cookie Hygiene**:
    - The `AuthStateCookie` MUST be **encrypted** (confidentiality) and authenticated (integrity).
    - It MUST be `HttpOnly`, `Secure`, and `SameSite=Lax`.
    - To prevent cookie overflow/DoS, the `AuthStateMap` MUST be capped (e.g., max 3 pending flows), evicting the oldest `AuthState` if full.
    - `AuthState` MUST be removed immediately upon retrieval to prevent replay.
4.  **Open Redirect Prevention**:
    - The `next_url` MUST be validated when the flow starts.
    - It MUST be a relative path (starting with `/` but not `//`) or match a strict allow-list.
    - If invalid, it defaults to `/`.

### Outputs
The handler should provide a single composable output result via a callback hook:
- `*oauth2.Token` (access/refresh tokens)
- `*oidc.IDToken` (optional identity token, if available)

### Integration with application session
The handler itself should not hard-code how identity and credentials are stored; instead it should expose hooks for customization.

**Pre-Auth Hook (Optional)**
- Invoked during flow initiation (`/login/...`) after extracting parameters.
- Allows the app to validate or inject `next_url` and `AppData`.
- `AppData` originates from the `app_data` query parameter, but can be overridden or injected by this handler (e.g. to attach session context).
- `type PreAuthHook func(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID string, params AuthParams) (AuthParams, error)`
- `type AuthParams struct { NextURL string; AppData string }` (Fields annotated with cbor/json tags)

**Success Endpoint**
- After a successful callback, the handler invokes the SuccessEndpoint with `SuccessParams`.
- The application needs to decide how to handle these (e.g., log the user in, store tokens, or both) and return a Renderer.

Proposed hook (illustrative):
- `type SuccessEndpoint endpoint.EndpointFunc[*SuccessParams]`
- `type SuccessParams struct { ProviderID string; Token *oauth2.Token; IDToken *oidc.IDToken; AppData string; NextURL string }`

**Failure Endpoint**
- If the flow fails (provider error, state mismatch, invalid token), the handler invokes a failure endpoint instead of serving a raw 4xx/5xx page.
- Allows the app to redirect to a login page with an error message.
- `type FailureEndpoint endpoint.EndpointFunc[error]`

The `AuthHandler` should accept these via options (e.g., `WithSuccessEndpoint(...)`, `WithFailureEndpoint(...)`).

### Helper Functions
The library should provide helper functions to assist `SuccessHandler` implementations:
- `GetVerifiedEmail(token *oidc.IDToken) (string, bool)`: Returns the email address if `email_verified` claim is true.
- `GetStableID(token *oidc.IDToken, providerID string) string`: Returns a stable, collision-resistant identifier (e.g., `providerID:subject`).

## Trade-offs / Risks
- OIDC validation requires key discovery (JWKS) and careful clock/issuer/audience validation.
- Cookie-session storage is size-limited; pending flow state should be minimal.
- Concurrency requirements imply flow IDs must be unique and stored as a map keyed by flow.

## Open Questions
(None; decisions regarding claim mapping and credential storage have been made and documented.)
