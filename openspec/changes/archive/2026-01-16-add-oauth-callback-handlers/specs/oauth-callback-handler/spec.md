# oauth-callback-handler (delta)

## ADDED Requirements

### Requirement: OAuth Flow Initiation
The system SHALL provide an HTTP handler to initiate OAuth flows.

#### Scenario: Login route redirects to provider
- **GIVEN** the handler is mounted at `/<base>`
- **WHEN** a request is made to `/<base>/login/{provider}` (optionally with `next_url` and `app_data`)
- **AND** a `PreAuthHook` (if configured) validates/overrides these parameters
- **THEN** the handler MUST create a new flow state (nonce, PKCE verifier if enabled, etc).
- **AND** it MUST redirect the user to the provider's Authorization Endpoint.

### Requirement: Provider-aware OAuth callback handling
The system SHALL provide an HTTP handler component that can handle OAuth 2.0 authorization callbacks for multiple distinct providers.

#### Scenario: Callback route uses provider path segment
- **GIVEN** an application mounts the handler at a base path `/<base>`
- **AND** the callback route is available at `/<base>/callback/{provider}`
- **WHEN** the handler receives a callback request for a provider
- **THEN** it MUST determine the provider identifier from the `{provider}` path segment.

#### Scenario: Multiple providers concurrently
- **GIVEN** an application registers two providers, `microsoft` and `google`
- **AND** multiple browser sessions may initiate authorization flows concurrently
- **WHEN** callbacks arrive for both providers interleaved in time
- **THEN** the handler MUST route each callback to the correct provider configuration based on an explicit provider identifier.
- **AND** state/correlation for one provider MUST NOT be accepted for a different provider.

### Requirement: Application-configurable provider registration
The system MUST allow applications to configure and register one or more OAuth/OIDC providers with the auth handler.

#### Scenario: Provider registry is configured at handler construction
- **GIVEN** an application constructs the auth-root handler
- **WHEN** the application registers providers (e.g., Google and Microsoft)
- **THEN** the handler MUST store provider configurations keyed by a provider identifier.
- **AND** the handler MUST reject callback requests for unknown provider identifiers.

### Requirement: Public URL Configuration
The handler MUST be capable of correctly constructing `redirect_uri` values that match the application's external public address.

#### Scenario: Redirect URI construction
- **GIVEN** the handler is configured with a public base URL (e.g., `https://example.com`)
- **AND** the handler is mounted at `/<base>`
- **WHEN** an authorization flow is initiated for a provider
- **THEN** the `redirect_uri` sent to the provider MUST be absolute and match `https://example.com/<base>/callback/{provider}`.
- **AND** it MUST NOT be based on the incoming request's Host header (to prevent Host header injection attacks).

### Requirement: Correlation and CSRF state validation
The handler MUST validate callback requests using a correlation mechanism that prevents CSRF and supports multiple simultaneous in-flight flows.

#### Scenario: State parameter is an opaque identifier
- **GIVEN** an authorization request is initiated
- **WHEN** the handler generates the OAuth `state` parameter
- **THEN** the `state` value MUST be a random identifier suitable for passing in the OAuth `state` value.
- **AND** the `state` value MUST be treated as opaque by clients.

#### Scenario: State identifier maps to a cookie-stored state object
- **GIVEN** a browser has a secure cookie containing a map of pending OAuth flow state objects keyed by `state` identifier
- **WHEN** the handler receives a callback with a `state` identifier
- **THEN** the handler MUST look up the corresponding state object from the secure cookie.
- **AND** the handler MUST reject the callback if no corresponding state object exists.
- **AND** the state object MAY include fields such as an OIDC `nonce`, `next_url`, and user-supplied `AppData`.

#### Scenario: State cleanup (Replay Prevention)
- **GIVEN** a state object is successfully retrieved for a callback
- **WHEN** the callback processing completes (success or failure)
- **THEN** the handler MUST immediately remove that specific `AuthState` from the cookie map.
- **AND** subsequent uses of the same `state` identifier MUST fail.

#### Scenario: Multiple concurrent flows for a single user-agent
- **GIVEN** a single browser initiates two OAuth flows (possibly for the same provider)
- **WHEN** the browser completes both callbacks in any order
- **THEN** the handler MUST be able to validate each callback independently.
- **AND** completion of one flow MUST NOT invalidate the other.

#### Scenario: Invalid state
- **GIVEN** a callback request with an unknown, expired, or mismatched `state`
- **WHEN** the handler processes the callback
- **THEN** it MUST reject the request with an appropriate client error (4xx).

### Requirement: Strict Security Controls
The handler MUST enforce strict security controls including PKCE, strict OIDC validation, state cookie limits, and open redirect prevention.

#### Scenario: PKCE Enforcement
- **GIVEN** a provider supports PKCE
- **WHEN** the handler initiates a flow
- **THEN** it MUST generate a `code_verifier` and send a `code_challenge` (S256).
- **AND** it MUST send the `code_verifier` during the token exchange.

#### Scenario: Strict OIDC Validation
- **GIVEN** an OIDC ID Token is received
- **WHEN** the handler processes the token
- **THEN** it MUST validate the signature (JWKS), Issuer, Audience, Expiry.
- **AND** it MUST verify that the `nonce` claim in the ID Token exactly matches the `nonce` stored in the `AuthState` cookie.

#### Scenario: State Cookie Hygiene (DoS Prevention & Confidentiality)
- **GIVEN** the handler stores state in a cookie
- **WHEN** the cookie is written
- **THEN** the cookie content MUST be encrypted (confidentiality) and signed (integrity).
- **AND** if the number of pending flows exceeds a configured limit (e.g., 3), the handler MUST evict the oldest `AuthState` to prevent cookie overflow.

#### Scenario: Open Redirect Prevention
- **GIVEN** a flow is initiated
- **WHEN** the `PreAuthHook` (if any) has run and returned a `next_url`
- **THEN** the handler MUST validate the `next_url` BEFORE starting the flow.
- **AND** it MUST ensure the URL is relative (starts with `/` but not `//`) or matches a strict allow-list.
- **AND** if invalid, it MUST default to `/`.

### Requirement: OAuth authorization code exchange for provider credentials
The handler MUST support exchanging an OAuth authorization `code` for provider credentials suitable for calling provider APIs.

#### Scenario: Google Calendar credentials acquisition
- **GIVEN** a provider configuration for Google OAuth with calendar scopes
- **WHEN** the handler receives a valid callback containing an authorization `code`
- **THEN** the handler MUST exchange the `code` for tokens/credentials.
- **AND** the handler MUST make the resulting credentials available for later use by a Google Calendar client.

### Requirement: Mapping OAuth results into application session
The system MUST provide a single unified integration mechanism for applications to map successful OAuth/OIDC results into their session model.

#### Scenario: Unified Success Callback
- **GIVEN** an application defines a success endpoint
- **WHEN** a callback completes successfully (login, credential, or both)
- **THEN** the handler MUST invoke the success endpoint with the `SuccessParams` (provider ID, Token, optional IDToken, AppData, NextURL).

#### Scenario: Simultaneous Login and Credential Flow
- **GIVEN** a provider flow that requests both OIDC scopes and API scopes
- **WHEN** the callback completes
- **THEN** the handler MUST provide both the Access Token (for API access) and the ID Token (for identity) to the success endpoint simultaneously.

### Requirement: Optional OIDC ID token processing
The handler MUST optionally support processing OIDC ID tokens returned by OAuth/OIDC providers.

#### Scenario: Microsoft login uses ID token; username extracted
- **GIVEN** a provider configuration for Microsoft login that yields an OIDC ID token
- **WHEN** the handler completes the callback flow successfully
- **THEN** it MUST be able to extract a stable user identifier ("username") from the ID token claims.
- **AND** it MUST make that identifier available to the application (e.g., for session login).

#### Scenario: “Check for OIDC token from Google” during Microsoft login
- **GIVEN** a Microsoft login callback is being processed
- **AND** the application is configured to optionally accept a Google OIDC token in the same request context
- **WHEN** the handler finds a Google OIDC token present
- **THEN** it MUST be able to validate/process that token using the Google provider configuration.
- **AND** it MUST be able to extract the username from that token.

### Requirement: OIDC Identity Helpers
The system MUST provide utility functions to assist developers in safely extracting identity information from ID tokens.

#### Scenario: Safely extract verified email
- **GIVEN** a valid OIDC ID Token
- **WHEN** the `GetVerifiedEmail` helper is called
- **THEN** it MUST return the email address only if the `email_verified` claim is present and true.
- **AND** it MUST return false/empty if the email is unverified.

#### Scenario: Generate stable user ID
- **GIVEN** a valid OIDC ID Token and a provider identifier
- **WHEN** the `GetStableID` helper is called
- **THEN** it MUST return a unique, collision-resistant string based on the provider ID and the OIDC `sub` (subject) claim (e.g., `google:12345`).

### Requirement: Provider error propagation
The handler MUST surface provider-declared errors via a failure handler.

#### Scenario: OAuth provider returns error
- **GIVEN** a callback request includes OAuth error parameters (e.g., `error`, `error_description`)
- **WHEN** the handler processes the callback
- **THEN** it MUST invoke the configured `FailureEndpoint` with the error details.
- **AND** it MUST NOT render a default error page if a `FailureEndpoint` is provided.

