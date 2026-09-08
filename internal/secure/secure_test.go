package secure

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestVaultAuthenticatedEncryption(t *testing.T) {
	v, err := NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	plain := "sensitive AWS secret"
	one, two := v.Encrypt(plain), v.Encrypt(plain)
	if one == two || strings.Contains(one, plain) {
		t.Fatal("ciphertext must be randomized")
	}
	got, err := v.Decrypt(one)
	if err != nil || got != plain {
		t.Fatal("round trip failed")
	}
	b, _ := base64.StdEncoding.DecodeString(one)
	b[len(b)-1] ^= 1
	if _, err = v.Decrypt(base64.StdEncoding.EncodeToString(b)); err == nil {
		t.Fatal("tampering accepted")
	}
	if _, err = v.Decrypt("abc"); err == nil {
		t.Fatal("malformed ciphertext accepted")
	}
}
func TestVaultRejectsInvalidKeys(t *testing.T) {
	for _, key := range []string{"", "not-base64", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		if _, err := NewVault(key); err == nil {
			t.Fatalf("accepted invalid key %q", key)
		}
	}
}

func TestVaultDecryptsLegacyCCMPCredentials(t *testing.T) {
	v, err := NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, v.a.NonceSize())
	legacy := base64.StdEncoding.EncodeToString(v.a.Seal(nonce, nonce, []byte("legacy secret"), []byte(legacyCredentialsAAD)))
	plain, err := v.Decrypt(legacy)
	if err != nil || plain != "legacy secret" {
		t.Fatalf("legacy decrypt = %q, %v", plain, err)
	}
}
