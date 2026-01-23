package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"github.com/mnehpets/oneserve/auth"
	"github.com/mnehpets/oneserve/endpoint"
	"github.com/mnehpets/oneserve/middleware"
)

// HomeParams are the parameters for the home endpoint.
type HomeParams struct{}

// HomeData is the data passed to the template.
type HomeData struct {
	LoggedIn bool
	Username string
}

const homeTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Auth Example</title>
</head>
<body>
	<h1>Auth Example</h1>
	{{if .LoggedIn}}
		<p>Welcome, {{.Username}}!</p>
		<a href="/auth/logout?next_url=/home/">Logout</a>
	{{else}}
		<p>You are not logged in.</p>
		<a href="/auth/login/google?next_url=/home/">Login with Google</a>
	{{end}}
</body>
</html>
`

// HomeEndpoint handles requests to the root path.
func HomeEndpoint(w http.ResponseWriter, r *http.Request, params HomeParams) (endpoint.Renderer, error) {
	session, ok := middleware.SessionFromContext(r.Context())
	data := HomeData{}
	if ok {
		if username, loggedIn := session.Username(); loggedIn {
			data.LoggedIn = true
			data.Username = username
		}
	}

	tmpl, err := template.New("home").Parse(homeTemplate)
	if err != nil {
		return nil, endpoint.Error(http.StatusInternalServerError, "template error", err)
	}

	return &endpoint.HTMLTemplateRenderer{
		Template: tmpl,
		Values:   data,
	}, nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET must be set")
	}

	// 1. Setup Session Processor
	// For example purposes, we generate a random key. In production, this should be persisted.
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		log.Fatal(err)
	}

	// Using "OSS" as cookie name (default). Allow non-https cookies, for http://localhost:8080
	sessionProcessor, err := middleware.NewSessionProcessor(
		middleware.DefaultCookieName,
		"key1",
		map[string][]byte{"key1": sessionKey},
		middleware.WithCookieOptions(
			middleware.WithSecure(false),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Setup Auth Handler
	registry := auth.NewRegistry()
	ctx := context.Background()
	redirectURL := "http://localhost:8080/auth/callback/google"

	// Using Google as the provider
	err = registry.RegisterOIDCProvider(ctx,
		"google",
		"https://accounts.google.com",
		clientID,
		clientSecret,
		[]string{oidc.ScopeOpenID, "profile", "email"},
		redirectURL,
	)
	if err != nil {
		log.Fatalf("Failed to register OIDC provider: %v", err)
	}

	// Use "OSA" as cookie name (default). Also allow non-https for http://localhost:8080.
	authHandler, err := auth.NewHandler(registry, auth.DefaultCookieName, "key1", map[string][]byte{"key1": sessionKey}, "http://localhost:8080", "/auth",
		auth.WithCookieOptions(
			middleware.WithSecure(false),
		),
		auth.WithSuccessEndpoint(func(w http.ResponseWriter, r *http.Request, params *auth.SuccessParams) (endpoint.Renderer, error) {
			session, ok := middleware.SessionFromContext(r.Context())
			if !ok {
				return nil, fmt.Errorf("session not found in context")
			}

			email, verified := auth.GetVerifiedEmail(params.IDToken)
			if !verified {
				return nil, endpoint.Error(http.StatusUnauthorized, "email not verified", nil)
			}
			fmt.Printf("Successful authenticated with provider %v, nextURL %v, verified email %v\n", params.ProviderID, params.NextURL, email)
			if err := session.Login(email); err != nil {
				return nil, endpoint.Error(http.StatusInternalServerError, "login failed", err)
			}

			// Redirect to NextURL or root
			target := params.NextURL
			if target == "" {
				target = "/"
			}
			return &endpoint.RedirectRenderer{URL: target, Status: http.StatusFound}, nil
		}),
		auth.WithProcessors(sessionProcessor),
	)
	if err != nil {
		log.Fatalf("Failed to create auth handler: %v", err)
	}

	// 3. Setup Router
	mux := http.NewServeMux()

	// Mount Auth Handler
	mux.Handle("/auth/", authHandler)

	// Mount Logout Handler
	mux.HandleFunc("/auth/logout", endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, params struct {
		NextURL string `query:"next_url"`
	}) (endpoint.Renderer, error) {
		session, ok := middleware.SessionFromContext(r.Context())
		if ok {
			session.Logout()
		}
		next := auth.ValidateNextURLIsLocal(params.NextURL)
		return &endpoint.RedirectRenderer{URL: next, Status: http.StatusFound}, nil
	}, sessionProcessor))

	// Mount Home Handler (using session middleware handled by root wrapper)
	mux.HandleFunc("/home/", endpoint.HandleFunc(HomeEndpoint, sessionProcessor))

	// Add minimal root handler
	mux.HandleFunc("/", endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.StringRenderer{Body: "Welcome to the Auth Example! Visit /home/ to see your login status.", Status: http.StatusOK}, nil
	}))

	log.Println("Listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
