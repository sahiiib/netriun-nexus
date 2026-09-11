package app

import (
	"errors"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

func normalizeEmail(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if len(value) < 3 || len(value) > 254 || !utf8.ValidString(value) {
		return "", errors.New("email must be a valid address")
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || !strings.Contains(value, "@") {
		return "", errors.New("email must be a valid address")
	}
	return value, nil
}

func strongPassword(value string) error {
	if len(value) < 10 || len(value) > 72 || !utf8.ValidString(value) {
		return errors.New("password must be 10–72 bytes")
	}
	var lower, upper, digit, symbol bool
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbol = true
		}
	}
	if !lower || !upper || !digit || !symbol {
		return errors.New("password must include uppercase, lowercase, number, and symbol")
	}
	return nil
}
