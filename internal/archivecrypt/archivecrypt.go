// Package archivecrypt is the format of encrypted archive objects and wrapped data keys (G6-07),
// shared by the archiver and `wtctl archive decrypt`. Objects are
// `"WTE1" ‖ nonce(12) ‖ AES-256-GCM(data key, aad = project id text)`; a data key is wrapped as
// `0x01 ‖ 0x01 ‖ nonce(12) ‖ ciphertext` (the wt-secrets format) under
// HKDF-SHA256(WT_SECRET_KEY, salt "watchtower", info DataKeyInfo), aad = the project's uuid bytes.
package archivecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
)

// DataKeyInfo is the HKDF info of the key that wraps data keys.
const DataKeyInfo = "wt/tenant-data-key/v1"

// Magic starts every encrypted object.
var Magic = []byte("WTE1")

// IsEncrypted reports whether b is an encrypted object (anything else is legacy plaintext).
func IsEncrypted(b []byte) bool { return bytes.HasPrefix(b, Magic) }

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// NewDataKey is a fresh random 32-byte key.
func NewDataKey() ([]byte, error) {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	return k, err
}

// Seal encrypts an object for project (the uuid text).
func Seal(dk []byte, project string, data []byte) ([]byte, error) {
	g, err := gcm(dk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, Magic...), nonce...), g.Seal(nil, nonce, data, []byte(project))...), nil
}

// Open decrypts an object; data without the magic is returned unchanged.
func Open(dk []byte, project string, b []byte) ([]byte, error) {
	if !IsEncrypted(b) {
		return b, nil
	}
	g, err := gcm(dk)
	if err != nil {
		return nil, err
	}
	n := len(Magic) + g.NonceSize()
	if len(b) < n+g.Overhead() {
		return nil, errors.New("truncated encrypted object")
	}
	pt, err := g.Open(nil, b[len(Magic):n], b[n:], []byte(project))
	if err != nil {
		return nil, errors.New("cannot decrypt (wrong key or tampered object)")
	}
	return pt, nil
}

func wrapKey(master string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(master), []byte("watchtower"), DataKeyInfo, 32)
}

// Wrap seals a data key under the master key.
func Wrap(master string, project uuid.UUID, dk []byte) ([]byte, error) {
	wk, err := wrapKey(master)
	if err != nil {
		return nil, err
	}
	g, err := gcm(wk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(append([]byte{1, 1}, nonce...), g.Seal(nil, nonce, dk, project[:])...), nil
}

// Unwrap opens a wrapped data key.
func Unwrap(master string, project uuid.UUID, sealed []byte) ([]byte, error) {
	wk, err := wrapKey(master)
	if err != nil {
		return nil, err
	}
	g, err := gcm(wk)
	if err != nil {
		return nil, err
	}
	if len(sealed) < 14+g.Overhead() || sealed[0] != 1 || sealed[1] != 1 {
		return nil, errors.New("data key: unknown sealed format")
	}
	dk, err := g.Open(nil, sealed[2:14], sealed[14:], project[:])
	if err != nil {
		return nil, errors.New("data key: cannot open (wrong master key)")
	}
	return dk, nil
}
