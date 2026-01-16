## 1. Discovery / Alignment
- [x] 1.1 Confirm routing: single auth-root handler mounted at `/<base>` with:
  - `/<base>/login/{provider}` (initiation)
  - `/<base>/callback/{provider}` (callback)
- [x] 1.2 Confirm state storage: `state` is random identifier; cookie stores map[stateID]AuthState (nonce, next_url, AppData...)
- [x] 1.3 Confirm identity claim mapping for OIDC username extraction
- [x] 1.4 Confirm where to store returned OAuth credentials (session KV vs external store)

## 2. Specs
- [x] 2.1 Add new capability delta spec: `specs/oauth-callback-handler/spec.md`
- [x] 2.2 Add scenarios for:
  - multi-provider concurrency
  - Microsoft login + optional OIDC token processing
  - Google Calendar credential acquisition
  - error handling (invalid state, provider error, token exchange failure)
  - failure handling (custom hook)

## 3. Implementation (after approval)
- [x] 3.1 Implement provider registry using `x/oauth2` and `go-oidc`
- [x] 3.2 Implement secure state/correlation:
  - [x] Random `state` generation
  - [x] Secure cookie storage (Encrypted, HttpOnly, Secure, Lax)
  - [x] Flow limiting (max N concurrent flows)
  - [x] State cleanup on retrieval
  - [x] `next_url` validation (post-PreAuthHandler)
- [x] 3.3 Implement handlers:
  - [x] Initiation Handler (`/login/{provider}`) with `PreAuthHandler` support
  - [x] Callback Handler with Unified Success Handler and Failure Handler
  - [x] **Public URL** configuration and correct `redirect_uri` construction
- [x] 3.4 Implement strict OIDC validation using `go-oidc` (Issuer, Aud, Exp, Nonce)
- [x] 3.5 Implement OIDC identity helpers:
  - [x] `GetVerifiedEmail` (checks email_verified claim)
  - [x] `GetStableID` (provider:sub format)
- [x] 3.6 Implement PKCE-enabled token exchange flow
- [x] 3.7 Add tests for concurrent providers and simultaneous login+credential flows

## 4. Validation
- [x] 4.1 `go test ./...`
- [x] 4.2 `openspec validate add-oauth-callback-handlers --strict`
