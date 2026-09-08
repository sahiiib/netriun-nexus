package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

type Vault struct{ a cipher.AEAD }

const (
	nexusCredentialsAAD  = "netriun-nexus:credentials:v1"
	legacyCredentialsAAD = "netriun-ccmp:credentials:v1"
)

func NewVault(key string) (*Vault, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be a base64 encoded 32-byte key")
	}
	c, err := aes.NewCipher(b)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(c)
	return &Vault{a}, err
}
func (v *Vault) Encrypt(s string) string {
	n := make([]byte, v.a.NonceSize())
	if _, err := rand.Read(n); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(v.a.Seal(n, n, []byte(s), []byte(nexusCredentialsAAD)))
}
func (v *Vault) Decrypt(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	n := v.a.NonceSize()
	if len(b) < n {
		return "", errors.New("invalid ciphertext")
	}
	p, err := v.a.Open(nil, b[:n], b[n:], []byte(nexusCredentialsAAD))
	if err != nil {
		// Keep credentials written before the Nexus rebrand readable. They are
		// re-encrypted with the Nexus context the next time an account is saved.
		p, err = v.a.Open(nil, b[:n], b[n:], []byte(legacyCredentialsAAD))
	}
	return string(p), err
}
