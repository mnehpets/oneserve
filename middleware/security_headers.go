package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/mnehpets/oneserve/endpoint"
)

// SecurityHeadersProcessor is a middleware that sets recommended security headers.
//
// Default configuration provides secure defaults:
//   - HSTS: max-age=31536000; includeSubDomains (1 year, with subdomains)
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - X-Frame-Options: DENY
//   - X-Content-Type-Options: nosniff
//
// For cross-origin scenarios, configure CORS options via CORSConfig.
type SecurityHeadersProcessor struct {
	// HSTS configures the Strict-Transport-Security header.
	// Set to nil to disable. Default: max-age=31536000; includeSubDomains
	HSTS *HSTSConfig

	// ReferrerPolicy sets the Referrer-Policy header.
	// Set to empty string to disable. Default: strict-origin-when-cross-origin
	ReferrerPolicy string

	// FrameOptions sets the X-Frame-Options header.
	// Set to empty string to disable. Default: DENY
	// Common values: DENY, SAMEORIGIN, or empty to disable
	FrameOptions string

	// ContentTypeOptions sets the X-Content-Type-Options header.
	// Set to false to disable. Default: true (nosniff)
	ContentTypeOptions bool

	// CORS configures Cross-Origin Resource Sharing headers.
	// Set to nil to disable CORS headers.
	CORS *CORSConfig
}

// HSTSConfig configures HTTP Strict Transport Security.
type HSTSConfig struct {
	// MaxAge specifies the duration (in seconds) that the browser should remember
	// that a site is only to be accessed using HTTPS.
	// Default: 31536000 (1 year)
	MaxAge int

	// IncludeSubDomains indicates whether HSTS applies to subdomains.
	// Default: true
	IncludeSubDomains bool

	// Preload indicates whether the site should be included in browsers' HSTS preload lists.
	// Only use if you've submitted your domain to the HSTS preload list.
	// Default: false
	Preload bool
}

// CORSConfig configures Cross-Origin Resource Sharing headers.
type CORSConfig struct {
	// AllowedOrigins specifies allowed origins for CORS requests.
	// Use "*" to allow any origin (not recommended for production).
	// Use specific origins like "https://example.com" for better security.
	// Default: nil (no CORS headers)
	AllowedOrigins []string

	// AllowedMethods specifies allowed HTTP methods for CORS requests.
	// Default: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
	AllowedMethods []string

	// AllowedHeaders specifies allowed headers for CORS requests.
	// Default: ["Accept", "Content-Type", "Authorization"]
	AllowedHeaders []string

	// ExposedHeaders specifies headers that are safe to expose to the API.
	// Default: nil
	ExposedHeaders []string

	// AllowCredentials indicates whether credentials (cookies, auth headers) can be sent.
	// Default: false
	AllowCredentials bool

	// MaxAge indicates how long (in seconds) preflight request results can be cached.
	// Default: 3600 (1 hour)
	MaxAge int
}

// NewSecurityHeadersProcessor creates a SecurityHeadersProcessor with recommended defaults.
func NewSecurityHeadersProcessor() *SecurityHeadersProcessor {
	return &SecurityHeadersProcessor{
		HSTS: &HSTSConfig{
			MaxAge:            31536000, // 1 year
			IncludeSubDomains: true,
			Preload:           false,
		},
		ReferrerPolicy:     "strict-origin-when-cross-origin",
		FrameOptions:       "DENY",
		ContentTypeOptions: true,
		CORS:               nil, // No CORS by default
	}
}

// WithHSTS configures HSTS settings.
func (p *SecurityHeadersProcessor) WithHSTS(maxAge int, includeSubDomains, preload bool) *SecurityHeadersProcessor {
	p.HSTS = &HSTSConfig{
		MaxAge:            maxAge,
		IncludeSubDomains: includeSubDomains,
		Preload:           preload,
	}
	return p
}

// WithoutHSTS disables HSTS headers.
func (p *SecurityHeadersProcessor) WithoutHSTS() *SecurityHeadersProcessor {
	p.HSTS = nil
	return p
}

// WithReferrerPolicy sets the Referrer-Policy header.
// Common values: no-referrer, no-referrer-when-downgrade, origin,
// origin-when-cross-origin, same-origin, strict-origin,
// strict-origin-when-cross-origin, unsafe-url
func (p *SecurityHeadersProcessor) WithReferrerPolicy(policy string) *SecurityHeadersProcessor {
	p.ReferrerPolicy = policy
	return p
}

// WithFrameOptions sets the X-Frame-Options header.
// Common values: DENY, SAMEORIGIN
func (p *SecurityHeadersProcessor) WithFrameOptions(options string) *SecurityHeadersProcessor {
	p.FrameOptions = options
	return p
}

// WithContentTypeOptions enables or disables X-Content-Type-Options: nosniff.
func (p *SecurityHeadersProcessor) WithContentTypeOptions(enabled bool) *SecurityHeadersProcessor {
	p.ContentTypeOptions = enabled
	return p
}

// WithCORS configures CORS headers for cross-origin access.
func (p *SecurityHeadersProcessor) WithCORS(config *CORSConfig) *SecurityHeadersProcessor {
	p.CORS = config
	return p
}

// Process implements endpoint.Processor.
func (p *SecurityHeadersProcessor) Process(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) error) error {
	// Set HSTS header
	if p.HSTS != nil {
		hsts := formatHSTS(p.HSTS)
		if hsts != "" {
			w.Header().Set("Strict-Transport-Security", hsts)
		}
	}

	// Set Referrer-Policy header
	if p.ReferrerPolicy != "" {
		w.Header().Set("Referrer-Policy", p.ReferrerPolicy)
	}

	// Set X-Frame-Options header
	if p.FrameOptions != "" {
		w.Header().Set("X-Frame-Options", p.FrameOptions)
	}

	// Set X-Content-Type-Options header
	if p.ContentTypeOptions {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}

	// Set CORS headers
	if p.CORS != nil {
		setCORSHeaders(w, r, p.CORS)
	}

	return next(w, r)
}

// formatHSTS formats the HSTS header value.
func formatHSTS(config *HSTSConfig) string {
	if config == nil || config.MaxAge <= 0 {
		return ""
	}

	var parts []string
	parts = append(parts, "max-age="+strconv.Itoa(config.MaxAge))

	if config.IncludeSubDomains {
		parts = append(parts, "includeSubDomains")
	}

	if config.Preload {
		parts = append(parts, "preload")
	}

	return strings.Join(parts, "; ")
}

// setCORSHeaders sets CORS headers based on the configuration.
func setCORSHeaders(w http.ResponseWriter, r *http.Request, config *CORSConfig) {
	if config == nil {
		return
	}

	// CORS headers should only be set when there's an actual cross-origin request
	// (Origin header present, per CORS spec). Without an Origin header, this is not
	// a cross-origin request and CORS headers are not needed.
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	// Set Access-Control-Allow-Origin
	if len(config.AllowedOrigins) > 0 {
		// Check if origin is allowed
		for _, allowed := range config.AllowedOrigins {
			if allowed == "*" {
				// Security: Never set wildcard origin with credentials - this would
				// expose credentials to all origins, violating the CORS security model.
				// The CORS spec explicitly forbids '*' with credentials.
				if config.AllowCredentials {
					// Skip wildcard when credentials are enabled
					continue
				}
				w.Header().Set("Access-Control-Allow-Origin", "*")
				break
			} else if allowed == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
	}

	// Set Access-Control-Allow-Credentials
	if config.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Set Access-Control-Expose-Headers (for simple requests)
	if len(config.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
	}

	// Preflight-specific headers (only for OPTIONS requests)
	if r.Method == "OPTIONS" {
		// Set Access-Control-Allow-Methods
		if len(config.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		}

		// Set Access-Control-Allow-Headers
		if len(config.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		}

		// Set Access-Control-Max-Age for preflight requests
		if config.MaxAge > 0 {
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
		}
	}
}

var _ endpoint.Processor = (*SecurityHeadersProcessor)(nil)
