package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider represents a configured OAuth/OIDC provider.
type Provider struct {
	id           string
	config       *oauth2.Config
	oidcProvider *oidc.Provider        // Optional: nil if not OIDC
	verifier     *oidc.IDTokenVerifier // Optional: nil if not OIDC
	usePKCE      bool
}

// NewProvider creates a new Provider instance.
// For OIDC providers, pass a non-nil oidcProvider.
func NewProvider(id string, config *oauth2.Config, oidcProvider *oidc.Provider, verifier *oidc.IDTokenVerifier) *Provider {
	return &Provider{
		id:           id,
		config:       config,
		oidcProvider: oidcProvider,
		verifier:     verifier,
		usePKCE:      true, // Default to true, maybe configurable later
	}
}

// ID returns the provider identifier.
func (p *Provider) ID() string {
	return p.id
}

// Config returns the oauth2.Config for the provider.
func (p *Provider) Config() *oauth2.Config {
	return p.config
}

// Verifier returns the OIDC IDTokenVerifier, if available.
func (p *Provider) Verifier() *oidc.IDTokenVerifier {
	return p.verifier
}

// SetPKCE enables or disables PKCE for this provider.
func (p *Provider) SetPKCE(enable bool) {
	p.usePKCE = enable
}

// Registry manages the set of registered providers.
type Registry struct {
	providers map[string]*Provider
}

// NewRegistry creates a new, empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]*Provider),
	}
}

// Register adds a provider to the registry.
func (r *Registry) Register(p *Provider) {
	r.providers[p.ID()] = p
}

// Get retrieves a provider by ID.
func (r *Registry) Get(id string) (*Provider, bool) {
	p, ok := r.providers[id]
	return p, ok
}

// RegisterOIDCProvider creates and registers an OIDC provider.
// This is a helper that performs discovery and setup.
func (r *Registry) RegisterOIDCProvider(ctx context.Context, id, issuer, clientID, clientSecret string, scopes []string, redirectURL string) error {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to query provider %q: %v", issuer, err)
	}

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	// Default verifier
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	p := NewProvider(id, conf, provider, verifier)
	r.Register(p)
	return nil
}

// RegisterOAuth2Provider registers a standard OAuth2 provider (without OIDC discovery).
// This is useful for providers that do not support OIDC or when only an access token is needed.
func (r *Registry) RegisterOAuth2Provider(id string, config *oauth2.Config) {
	p := NewProvider(id, config, nil, nil)
	r.Register(p)
}
