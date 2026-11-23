package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setUpAdmin opens a store and finishes setup with admin "admin".
func setUpAdmin(t *testing.T, password string) (*Store, string, []string) {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "instance.key")
	s, err := Open(dir, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	code, err := s.NewSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	seed := NewSeed()
	recovery, err := s.FinishSetup(Setup{Code: code, OrgName: "Alpha LLC", Domain: "alpha.e2e.test", Server: "mohur.alpha.e2e.test",
		Username: "admin", Password: password, Seed: seed, TOTP: TOTP(seed, time.Now().Add(-30*time.Second))})
	if err != nil {
		t.Fatal(err)
	}
	return s, keyFile, recovery
}

func TestResetCodeLetsTheAdminBackInOnce(t *testing.T) {
	const oldPassword, newPassword = "the old password nobody remembers", "a brand new admin password"
	s, keyFile, oldRecovery := setUpAdmin(t, oldPassword)
	now := time.Now()
	s.SetClock(func() time.Time { return now })

	code, err := ResetCode(keyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 24 || !s.CheckResetCode(code) || s.AdminName() != "admin" {
		t.Fatalf("fresh code %q: check %v, admin %q", code, s.CheckResetCode(code), s.AdminName())
	}
	// Grouped and lower case, as people copy it, still works.
	if !s.CheckResetCode(strings.ToLower(code[:4] + "-" + code[4:])) {
		t.Fatal("a grouped lower-case code was refused")
	}

	seed := NewSeed()
	in := Reset{Code: code, Username: "admin", Password: newPassword, Seed: seed, TOTP: "000000"}
	if TOTP(seed, now) == "000000" {
		in.TOTP = "111111"
	}
	// A wrong authenticator code or a short password changes nothing and
	// leaves the code usable.
	if _, err := s.ResetAdmin(in); !errors.Is(err, ErrRefused) {
		t.Fatalf("wrong authenticator code: %v", err)
	}
	in.TOTP = TOTP(seed, now)
	short := in
	short.Password = "too short"
	if _, err := s.ResetAdmin(short); !errors.Is(err, ErrRefused) {
		t.Fatalf("short password: %v", err)
	}
	unknown := in
	unknown.Username = "nobody"
	if _, err := s.ResetAdmin(unknown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown admin: %v", err)
	}
	if !s.CheckResetCode(code) {
		t.Fatal("a refused attempt spent the code")
	}
	if err := s.SignIn("admin", oldPassword, oldRecovery[0]); err != nil {
		t.Fatalf("old access before the reset: %v", err)
	}

	recovery, err := s.ResetAdmin(in)
	if err != nil || len(recovery) != 10 {
		t.Fatalf("reset: %d codes, %v", len(recovery), err)
	}
	if s.CheckResetCode(code) {
		t.Fatal("a used code still checks")
	}
	if _, err := s.ResetAdmin(in); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second use: %v", err)
	}
	if err := s.SignIn("admin", oldPassword, oldRecovery[1]); err == nil {
		t.Fatal("the old password still works")
	}
	if err := s.SignIn("admin", newPassword, oldRecovery[2]); err == nil {
		t.Fatal("an old recovery code still works")
	}
	if err := s.SignIn("admin", newPassword, recovery[0]); err != nil {
		t.Fatalf("new password and recovery code: %v", err)
	}
	now = now.Add(31 * time.Second)
	if err := s.SignIn("admin", newPassword, TOTP(seed, now)); err != nil {
		t.Fatalf("new password and authenticator: %v", err)
	}
}

func TestResetCodeRefusals(t *testing.T) {
	s, keyFile, _ := setUpAdmin(t, "the old password nobody remembers")
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	code, err := ResetCode(keyFile, now)
	if err != nil {
		t.Fatal(err)
	}

	// An hour is the limit.
	now = now.Add(ResetLifetime - time.Minute)
	if !s.CheckResetCode(code) {
		t.Fatal("refused within the hour")
	}
	now = now.Add(2 * time.Minute)
	if s.CheckResetCode(code) {
		t.Fatal("accepted after an hour")
	}
	seed := NewSeed()
	if _, err := s.ResetAdmin(Reset{Code: code, Username: "admin", Password: "a brand new admin password", Seed: seed, TOTP: TOTP(seed, now)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired code reset the admin: %v", err)
	}
	// A code dated in the future is not genuine either.
	future, _ := ResetCode(keyFile, now.Add(2*time.Minute))
	if s.CheckResetCode(future) {
		t.Fatal("accepted a code from the future")
	}

	now = time.Now()
	code, _ = ResetCode(keyFile, now)
	// Every changed character breaks it.
	for i := range code {
		c := []byte(code)
		c[i] = map[bool]byte{true: 'B', false: 'A'}[c[i] == 'A']
		if s.CheckResetCode(string(c)) {
			t.Fatalf("accepted the code with character %d changed", i)
		}
	}
	// Malformed input.
	for _, bad := range []string{"", "AAAA", code[:23], code + "A", code + "AAAAAAAA", strings.Repeat("1", 24), "!!!!" + code[4:]} {
		if s.CheckResetCode(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}

	// A code from another server's instance key.
	other := filepath.Join(t.TempDir(), "other.key")
	if err := os.WriteFile(other, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := ResetCode(other, now)
	if err != nil || s.CheckResetCode(foreign) {
		t.Fatalf("another server's code: %v", err)
	}

	// The command never creates a key, and refuses a wrong-sized one.
	missing := filepath.Join(t.TempDir(), "missing.key")
	if _, err := ResetCode(missing, now); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the reset command created an instance key")
	}
	if err := os.WriteFile(other, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResetCode(other, now); err == nil {
		t.Fatal("accepted a short instance key")
	}
}

func TestResetCodeNeedsAnAdmin(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "instance.key")
	s, err := Open(dir, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	code, err := ResetCode(keyFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s.CheckResetCode(code) || s.AdminName() != "" {
		t.Fatal("a reset code works before setup")
	}
}
