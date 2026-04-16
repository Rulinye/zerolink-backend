// Package auth holds password hashing, JWT signing, and the HTTP middleware.
//
// All bcrypt operations go through this package so the cost factor lives in
// one place. Per phase-1-handover §3.2: cost 12 (~250ms on 2026 hardware).
package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the cost factor for password hashing. See phase-1-handover §3.2
// for the rationale; raise to 13 in 2028 or whenever 250ms feels fast.
const BcryptCost = 12

// HashPassword returns a bcrypt hash for the given plaintext.
//
// The returned string is safe to store as-is; bcrypt encodes the salt and cost
// inside the hash. If you ever need to migrate cost factors, you can detect
// outdated hashes by parsing the cost field.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("auth: empty password")
	}
	if len(plain) > 72 {
		// bcrypt silently truncates input >72 bytes. Refuse rather than
		// hide that footgun.
		return "", errors.New("auth: password longer than 72 bytes")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plain), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword returns nil iff plain matches hash. ErrMismatchedHashAndPassword
// is bcrypt's "wrong password" sentinel; callers can check it via errors.Is.
func CheckPassword(hash, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}

// ErrMismatchedPassword aliases bcrypt's sentinel so callers don't need to
// import bcrypt directly.
var ErrMismatchedPassword = bcrypt.ErrMismatchedHashAndPassword
