package main

import (
	"log"
	"net/http"

	"github.com/mnehpets/oneserve/endpoint"
	"github.com/mnehpets/oneserve/middleware"
)

// APIParams defines the parameters for API endpoints.
type APIParams struct{}

// PublicAPIEndpoint is a simple API endpoint that returns JSON.
func PublicAPIEndpoint(w http.ResponseWriter, r *http.Request, params APIParams) (endpoint.Renderer, error) {
	return &endpoint.JSONRenderer{
		Value: map[string]string{
			"message": "Hello from secure API!",
			"status":  "ok",
		},
	}, nil
}

func main() {
	// Create security headers processor with default settings
	defaultSecurity := middleware.NewSecurityHeadersProcessor()

	// Create security headers processor with CORS enabled for cross-origin access
	corsSecurity := middleware.NewSecurityHeadersProcessor().WithCORS(&middleware.CORSConfig{
		AllowedOrigins: []string{"https://example.com", "https://app.example.com"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Content-Type", "Authorization"},
		ExposedHeaders: []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:         3600,
	})

	// Create a custom security configuration
	customSecurity := middleware.NewSecurityHeadersProcessor().
		WithHSTS(7776000, true, false). // 90 days, with subdomains, no preload
		WithReferrerPolicy("same-origin").
		WithFrameOptions("SAMEORIGIN")

	// Create a wildcard CORS configuration for public APIs
	publicCORS := middleware.NewSecurityHeadersProcessor().WithCORS(&middleware.CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         3600,
	})

	mux := http.NewServeMux()

	// Endpoint with default security headers
	mux.Handle("GET /api/secure", endpoint.HandleFunc(PublicAPIEndpoint, defaultSecurity))

	// Endpoint with CORS for specific origins
	mux.Handle("GET /api/cors", endpoint.HandleFunc(PublicAPIEndpoint, corsSecurity))

	// Endpoint with custom security settings
	mux.Handle("GET /api/custom", endpoint.HandleFunc(PublicAPIEndpoint, customSecurity))

	// Public endpoint with wildcard CORS
	mux.Handle("GET /api/public", endpoint.HandleFunc(PublicAPIEndpoint, publicCORS))

	log.Println("Server starting on :8080")
	log.Println("Try these endpoints:")
	log.Println("  - http://localhost:8080/api/secure  (default security headers)")
	log.Println("  - http://localhost:8080/api/cors    (CORS enabled for specific origins)")
	log.Println("  - http://localhost:8080/api/custom  (custom HSTS and frame options)")
	log.Println("  - http://localhost:8080/api/public  (public API with wildcard CORS)")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
