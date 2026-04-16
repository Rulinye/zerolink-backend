package auth

import (
	"strings"
	"testing"
	"time"
)

func mustSigner(t *testing.T) *Signer {
	t.Helper()
	secret, err := RandomSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(secret, time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewSigner_ShortSecret(t *testing.T) {
	if _, err := NewSigner([]byte("short"), time.Hour, "x"); err == nil {
		t.Fatal("want error for short secret")
	}
}

func TestIssueAndParse_RoundTrip(t *testing.T) {
	s := mustSigner(t)
	tok, claims, err := s.Issue(42, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != 42 || claims.Username != "alice" || !claims.IsAdmin {
		t.Fatalf("issued claims wrong: %+v", claims)
	}
	if claims.ID == "" {
		t.Fatal("jti must be non-empty")
	}

	parsed, err := s.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.UserID != 42 || parsed.Username != "alice" || !parsed.IsAdmin {
		t.Fatalf("parsed claims wrong: %+v", parsed)
	}
	if parsed.ID != claims.ID {
		t.Fatal("jti must round-trip")
	}
}

func TestParse_RejectsTamperedToken(t *testing.T) {
	s := mustSigner(t)
	tok, _, _ := s.Issue(1, "u", false)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal("expected 3-part JWT")
	}
	bad := parts[0] + "." + parts[1] + ".AAAA"
	if _, err := s.Parse(bad); err == nil {
		t.Fatal("want error on tampered signature")
	}
}

func TestParse_RejectsExpired(t *testing.T) {
	secret, _ := RandomSecret()
	s, err := NewSigner(secret, time.Millisecond, "test")
	if err != nil {
		t.Fatal(err)
	}
	tok, _, _ := s.Issue(1, "u", false)
	time.Sleep(10 * time.Millisecond)
	if _, err := s.Parse(tok); err == nil {
		t.Fatal("want error on expired token")
	}
}

func TestParse_RejectsWrongIssuer(t *testing.T) {
	secret, _ := RandomSecret()
	s1, _ := NewSigner(secret, time.Hour, "iss-a")
	s2, _ := NewSigner(secret, time.Hour, "iss-b")
	tok, _, _ := s1.Issue(1, "u", false)
	if _, err := s2.Parse(tok); err == nil {
		t.Fatal("want error when iss mismatch")
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPassword(hash, "correct horse battery staple"); err != nil {
		t.Fatal("expected match:", err)
	}
	if err := CheckPassword(hash, "wrong"); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestPassword_LengthGuards(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("empty password should fail")
	}
	long := make([]byte, 73)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := HashPassword(string(long)); err == nil {
		t.Fatal(">72 byte password should fail (bcrypt would silently truncate)")
	}
}
