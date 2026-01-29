## 1. Public API and implementation

- [x] 1.1 Add `ProxyRenderer` type in `endpoint/` that implements `endpoint.Renderer` and delegates to `httputil.ReverseProxy.ServeHTTP`
- [x] 1.2 Implement `NewProxyRenderer(targetURL string) (*ProxyRenderer, error)` using `url.Parse` and `httputil.NewSingleHostReverseProxy`
- [x] 1.3 Add godoc for `ProxyRenderer` and `NewProxyRenderer`, including example usage from an `EndpointFunc`
- [x] 1.4 Validate error behavior: `ProxyRenderer.Render` returns an error and does not write when `ProxyRenderer.Proxy` is nil
- [x] 1.5 Update `NewProxyRenderer` to rewrite the `Host` header to match the target URL

## 2. Tests

- [x] 2.1 Add unit test for `NewProxyRenderer` success with valid absolute URL
- [x] 2.2 Add unit tests for `NewProxyRenderer` rejecting empty, relative, and malformed URLs
- [x] 2.3 Add unit test that `ProxyRenderer.Render` errors when `ProxyRenderer.Proxy` is nil (and does not commit headers)
- [x] 2.4 Add integration-style test using `httptest.Server` verifying proxy forwards method/path/query, request body, and returns upstream response body
- [x] 2.5 Add test verifying hop-by-hop headers are not forwarded (request and response) when using the default proxy
- [x] 2.6 Add test verifying `Host` header is rewritten to target host

## 3. Documentation and examples

- [x] 3.1 Update `endpoint/endpoint.go` package comment list of supported renderers to include `ProxyRenderer`
- [x] 3.2 Add or update an example program under `example/` demonstrating an endpoint returning `ProxyRenderer`
- [x] 3.3 Ensure `go test ./...` passes
