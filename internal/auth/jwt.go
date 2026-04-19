package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the JWT payload. Per phase-1-handover §3.1.
type Claims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"sub"`
	IsAdmin  bool   `json:"adm"`
	jwt.RegisteredClaims
}

// Signer issues and verifies HS256-signed JWTs.
//
// The secret must be at least 32 bytes; we enforce this in NewSigner so a
// misconfigured deploy fails fast at startup rather than producing weak tokens.
type Signer struct {
	secret []byte
	ttl    time.Duration
	issuer string
}

// NewSigner constructs a Signer.
//
//   - secret: 32+ bytes of random material (read from env / vault).
//   - ttl:    token lifetime, e.g. 7*24*time.Hour for the default.
//   - issuer: free-form string, set to the service name for audit clarity.
func NewSigner(secret []byte, ttl time.Duration, issuer string) (*Signer, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("auth: jwt secret too short (%d bytes, need >=32)", len(secret))
	}
	if ttl <= 0 {
		return nil, errors.New("auth: jwt ttl must be positive")
	}
	return &Signer{secret: secret, ttl: ttl, issuer: issuer}, nil
}

// TTL returns the configured token lifetime. Handlers need this to compute
// expires_at when adding rows to the revoked_tokens table.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Issue mints a token for the given user. Returns (token, claims) so callers
// that need the jti for revocation can grab it.
func (s *Signer) Issue(userID int64, username string, isAdmin bool) (string, *Claims, error) {
	jti, err := newJTI()
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	claims := &Claims{
		UserID:   userID,
		Username: username,
		IsAdmin:  isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.secret)
	if err != nil {
		return "", nil, err
	}
	return signed, claims, nil
}

// Parse validates the token signature, exp, nbf, and iss. It does NOT consult
// the revocation list; the middleware does that separately so this package
// stays storage-free.
func (s *Signer) Parse(token string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("auth: unexpected signing method %v", t.Method.Alg())
			}
			return s.secret, nil
		},
		jwt.WithIssuer(s.issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return nil, err
	}
	c, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("auth: invalid token claims")
	}
	return c, nil
}

// newJTI returns a 16-byte base64url-encoded random ID. Used as the JWT jti
// claim and as the key in the revocation list.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomSecret generates a fresh JWT secret. Helper for the admin-create CLI
// or "generate me a secret" tooling.
func RandomSecret() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}
