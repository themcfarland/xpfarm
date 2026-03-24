package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

var encKey []byte

// Init loads the encryption key from data/.xpfarm.key, generating a new one if absent.
// Must be called once before Encrypt/Decrypt are used.
func Init() error {
	keyPath := "data/.xpfarm.key"

	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == 32 {
		encKey = data
		return nil
	}

	// Generate new 256-bit key
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("crypto: failed to create data dir: %w", err)
	}
	encKey = make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		return fmt.Errorf("crypto: failed to generate key: %w", err)
	}
	if err := os.WriteFile(keyPath, encKey, 0600); err != nil {
		return fmt.Errorf("crypto: failed to write key file: %w", err)
	}
	return nil
}

// Encrypt encrypts plaintext with AES-256-GCM.
// Returns "enc:<base64>" on success, or the original plaintext on failure (graceful degradation).
func Encrypt(plaintext string) string {
	if len(encKey) == 0 || plaintext == "" {
		return plaintext
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return plaintext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plaintext
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plaintext
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + base64.StdEncoding.EncodeToString(sealed)
}

// Decrypt decrypts a value produced by Encrypt.
// Values without the "enc:" prefix are returned as-is, enabling transparent migration
// from existing plaintext entries in the database.
func Decrypt(ciphertext string) string {
	if !strings.HasPrefix(ciphertext, "enc:") {
		return ciphertext
	}
	if len(encKey) == 0 {
		return ciphertext
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext[4:])
	if err != nil {
		return ciphertext
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return ciphertext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ciphertext
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ciphertext
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return ciphertext
	}
	return string(plaintext)
}
