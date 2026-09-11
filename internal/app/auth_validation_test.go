package app

import "testing"

func TestNormalizeEmail(t *testing.T) {
	got, err := normalizeEmail("  Owner@Example.COM ")
	if err != nil || got != "owner@example.com" {
		t.Fatalf("got %q, err=%v", got, err)
	}
	for _, value := range []string{"", "display <owner@example.com>", "not-an-email"} {
		if _, err = normalizeEmail(value); err == nil {
			t.Fatalf("invalid email %q accepted", value)
		}
	}
}

func TestStrongPassword(t *testing.T) {
	if err := strongPassword("Nexus-safe1!"); err != nil {
		t.Fatalf("strong password rejected: %v", err)
	}
	for _, value := range []string{"Short1!", "alllowercase1!", "ALLUPPERCASE1!", "NoDigitsHere!", "NoSymbols123"} {
		if err := strongPassword(value); err == nil {
			t.Fatalf("weak password %q accepted", value)
		}
	}
}
