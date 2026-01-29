# proxy-renderer Specification

## Purpose
Provide an `endpoint.Renderer` implementation that proxies the current request to an upstream HTTP endpoint using Go’s standard library reverse proxy behavior.

## ADDED Requirements

### Requirement: ProxyRenderer proxies via stdlib ReverseProxy
The system MUST provide a renderer named `ProxyRenderer` that forwards the incoming HTTP request to an upstream endpoint using the Go standard library reverse proxy implementation.

#### Scenario: ProxyRenderer is a terminal renderer
- **WHEN** a `ProxyRenderer` is returned by an `EndpointFunc`
- **THEN** `ProxyRenderer.Render` MUST be terminal (it MUST write the response and MUST NOT call any subsequent renderer)
- **AND** `ProxyRenderer.Render` MUST delegate response writing to the configured standard library reverse proxy.

#### Scenario: Request and response body preservation
- **WHEN** `ProxyRenderer` proxies a request to an upstream endpoint
- **THEN** the proxied request MUST preserve the incoming request body stream (no mandatory buffering)
- **AND** the response body returned to the client MUST be the upstream response body stream (no mandatory buffering).

#### Scenario: Hop-by-hop header handling
- **WHEN** `ProxyRenderer` proxies a request
- **THEN** hop-by-hop headers (as defined by HTTP semantics, including headers nominated by the `Connection` header) MUST NOT be forwarded to the upstream request
- **AND** hop-by-hop headers from the upstream response MUST NOT be forwarded to the client response.

#### Scenario: End-to-end header preservation
- **WHEN** `ProxyRenderer` proxies a request
- **THEN** request headers other than hop-by-hop and proxy-specific headers MUST be preserved from the incoming request, unless modified by the configured reverse proxy hooks
- **AND** response headers other than hop-by-hop and proxy-specific headers MUST be preserved from the upstream response, unless modified by the configured reverse proxy hooks.

#### Scenario: ReverseProxy configuration is provided by caller
- **WHEN** a `ProxyRenderer` is constructed for an endpoint
- **THEN** the caller MUST provide a fully-initialized `*net/http/httputil.ReverseProxy` to control upstream selection and rewrite behavior.

#### Scenario: Missing reverse proxy is an error
- **WHEN** `ProxyRenderer.Render` is called and the renderer has no configured reverse proxy
- **THEN** `ProxyRenderer.Render` MUST return a non-nil error
- **AND** it MUST NOT write response headers or body.

### Requirement: Convenience constructor for common proxy case
The system MUST provide a convenience function that constructs a `ProxyRenderer` from a target URL string using standard library defaults.

#### Scenario: NewProxyRenderer constructs a default ReverseProxy
- **WHEN** `NewProxyRenderer(targetURL)` is called with a valid absolute URL
- **THEN** it MUST return a `ProxyRenderer` whose reverse proxy is created using `net/http/httputil.NewSingleHostReverseProxy`
- **AND** the default reverse proxy MUST apply the standard library defaults for request rewriting and `X-Forwarded-*` handling
- **AND** the default reverse proxy MUST rewrite the `Host` header of the proxied request to match the host of the target URL.

#### Scenario: NewProxyRenderer rejects invalid target URLs
- **WHEN** `NewProxyRenderer(targetURL)` is called with an empty string or an invalid/relative URL
- **THEN** it MUST return a non-nil error.
