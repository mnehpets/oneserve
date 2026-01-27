package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// pkceVerifierLength is the number of random bytes used to generate the PKCE verifier.
// 32 bytes of random data results in a 43 character string (using RawURLEncoding), satisfying the
// RFC 7636 requirement (min 43 characters).
const pkceVerifierLength = 32

// generatePKCE creates a PKCE verifier and challenge.
// It uses S256 as the challenge method.
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, pkceVerifierLength)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)

	// SHA256 hash of the verifier for the challenge
	s := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(s[:])

	return verifier, challenge, nil
}

// DefaultCookieName is the default name for the auth state cookie.
const DefaultCookieName = "osa"

// GetVerifiedEmail returns the email address from the ID Token if the email_verified claim is true.
// Returns empty string and false if not verified or email is missing.
func GetVerifiedEmail(token *oidc.IDToken) (string, bool) {
	if token == nil {
		return "", false
	}
	var claims oidc.UserInfo
	if err := token.Claims(&claims); err != nil {
		return "", false
	}
	if !claims.EmailVerified {
		return "", false
	}
	return claims.Email, true
}

// GetStableID returns a stable identifier for the user based on the provider ID and the subject claim.
// Format: "provider:subject"
func GetStableID(token *oidc.IDToken, providerID string) string {
	if token == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s", providerID, token.Subject)
}

func ValidateNextURLIsLocal(nextURL string) string {
	// Simple check: must be relative (start with /) and not protocol-relative (start with //).
	if nextURL == "" || !strings.HasPrefix(nextURL, "/") || strings.HasPrefix(nextURL, "//") {
		return "/"
	}
	return nextURL
}
