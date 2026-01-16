# Change: Add OAuth callback handler capability

## Why
The project currently has an HTTP endpoint abstraction and session middleware, but no standardized way to handle OAuth/OIDC callback flows for multiple providers.

This change proposes a small, composable handler component that can:
- receive OAuth provider callbacks,
- exchange authorization codes for tokens/credentials,
- optionally validate/consume OIDC ID tokens for identity (login), and
- safely correlate concurrent callback flows across multiple providers.

## What Changes
- Introduce a new capability spec for an OAuth callback handler that supports:
  - multiple providers (e.g., Microsoft, Google) concurrently
  - correlation/state validation for callback requests
  - exchanging codes for provider credentials (e.g., Google Calendar access)
  - optional OIDC processing (e.g., extract username/subject from an ID token)
- Define error handling and response behaviors suitable for use with `endpoint.EndpointHandler`.
- Provide OIDC utility functions for common `SuccessHandler` tasks:
  - `GetVerifiedEmail(token)`: Safely extracts email if `email_verified` is true.
  - `GetStableID(token, providerID)`: Generates a stable, collision-resistant user ID (e.g. `provider|sub`) for storage.

## Impact
- Affected specs:
  - **New**: `oauth-callback-handler`
  - (No changes proposed to `http-endpoint` beyond integration expectations)
- Affected code (expected during implementation stage):
  - new handler/middleware package(s) for OAuth/OIDC callback orchestration
  - tests for multi-provider and concurrent-flow handling

## Out of Scope
- Full authn/authz framework (user database, roles, refresh token storage policies)
- UI/login pages, provider registration UX
- Long-term credential persistence beyond what is needed to demonstrate the flow

## Decisions
- Callback routing: provide a single auth-root handler mountable at an arbitrary base path (e.g. `/auth`), with callbacks at `/<base>/callback/{provider}`.
- State storage: the OAuth `state` parameter will be a random identifier used to look up a `AuthState` object in a `AuthStateMap` stored in a dedicated, encrypted secure cookie (carrying nonce, `next_url`, etc).
- OIDC identity claim: Exact claim mapping (`email`, `sub`, etc.) is delegated to the user-supplied `SuccessHandler`.
- Credential handoff: Credentials are passed to a pluggable `SuccessHandler` interface, allowing the application to decide storage (session, DB, etc.).

## Open Questions
(None)
