package endpoint

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ProxyRenderer is a Renderer that forwards the incoming request to an upstream endpoint
// using a configured ReverseProxy.
type ProxyRenderer struct {
	// Proxy is the ReverseProxy to use for forwarding the request.
	// It must be non-nil.
	Proxy *httputil.ReverseProxy
}

// NewProxyRenderer creates a new ProxyRenderer that forwards requests to the given target URL.
//
// It returns an error if the targetURL is empty, is not an absolute URL, or cannot be parsed.
// The created ProxyRenderer uses a default single-host ReverseProxy.
//
// Security Warning:
// Be cautious when using user-provided input to construct the targetURL. Failure to validate
// the URL can lead to Server-Side Request Forgery (SSRF) vulnerabilities, allowing attackers
// to access internal network resources.
//
// Additionally, ensure that the targetURL is trusted. If the URL points to a malicious site,
// the proxy may inadvertently forward sensitive headers (like cookies or authentication tokens)
// if they are not stripped, potentially leading to Cross-Site Request Forgery (XSRF) or session leaks.
//
// Example:
//
//	func MyEndpoint(w http.ResponseWriter, r *http.Request, params MyParams) (endpoint.Renderer, error) {
//		return endpoint.NewProxyRenderer("http://localhost:8080")
//	}
func NewProxyRenderer(targetURL string) (*ProxyRenderer, error) {
	if targetURL == "" {
		return nil, errors.New("endpoint: target URL is required")
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("endpoint: invalid target URL: %w", err)
	}

	if !target.IsAbs() {
		return nil, errors.New("endpoint: target URL must be absolute")
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	return &ProxyRenderer{
		Proxy: proxy,
	}, nil
}

// Render implements the Renderer interface.
//
// It delegates to the underlying Proxy to serve the HTTP request.
// It returns an error if the Proxy is nil.
func (p *ProxyRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	if p.Proxy == nil {
		return errors.New("endpoint: ProxyRenderer.Proxy is nil")
	}

	p.Proxy.ServeHTTP(w, r)
	return nil
}
