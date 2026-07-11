// Package securekey keeps software private keys encrypted while idle.
package securekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const referencePrefix = "securekey:"

type entry struct {
	wrappingKey  []byte
	nonce        []byte
	ciphertext   []byte
	plaintextLen int
	mu           sync.Mutex
}

var registry sync.Map

// Protect encrypts plaintext under fresh ephemeral wrapping material and
// returns an opaque process-local reference. plaintext is wiped before return.
func Protect(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot protect an empty key")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := bindWrappingKey(key); err != nil {
		wipe(key)
		return nil, fmt.Errorf("bind wrapping key to host: %w", err)
	}
	if err := protectMemory(key); err != nil {
		wipe(key)
		return nil, fmt.Errorf("protect wrapping key memory: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		unprotectMemory(key)
		wipe(key)
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		unprotectMemory(key)
		wipe(key)
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		unprotectMemory(key)
		wipe(key)
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	plaintextLen := len(plaintext)
	wipe(plaintext)

	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		unprotectMemory(key)
		wipe(key)
		return nil, err
	}
	id := hex.EncodeToString(idBytes)
	registry.Store(id, &entry{wrappingKey: key, nonce: nonce, ciphertext: ciphertext, plaintextLen: plaintextLen})
	return []byte(referencePrefix + id), nil
}

// WithPlaintext decrypts the referenced key into locked, non-dumpable scratch
// memory for the duration of fn and wipes it immediately afterwards.
func WithPlaintext(reference []byte, fn func([]byte) ([]byte, error)) ([]byte, error) {
	id, ok := strings.CutPrefix(string(reference), referencePrefix)
	if !ok || id == "" {
		return nil, errors.New("invalid protected-key reference")
	}
	value, ok := registry.Load(id)
	if !ok {
		return nil, errors.New("protected key is unavailable")
	}
	e := value.(*entry)
	e.mu.Lock()
	defer e.mu.Unlock()

	block, err := aes.NewCipher(e.wrappingKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(make([]byte, 0, e.plaintextLen), e.nonce, e.ciphertext, nil)
	if err != nil {
		return nil, errors.New("protected key authentication failed")
	}
	if err := protectMemory(plaintext); err != nil {
		wipe(plaintext)
		return nil, fmt.Errorf("protect plaintext scratch memory: %w", err)
	}
	defer func() {
		wipe(plaintext)
		unprotectMemory(plaintext)
	}()
	return fn(plaintext)
}

// Destroy removes a reference and wipes its ephemeral wrapping material.
func Destroy(reference []byte) error {
	id, ok := strings.CutPrefix(string(reference), referencePrefix)
	if !ok || id == "" {
		return errors.New("invalid protected-key reference")
	}
	value, ok := registry.LoadAndDelete(id)
	if !ok {
		return errors.New("protected key is unavailable")
	}
	e := value.(*entry)
	e.mu.Lock()
	defer e.mu.Unlock()
	wipe(e.wrappingKey)
	unprotectMemory(e.wrappingKey)
	wipe(e.nonce)
	wipe(e.ciphertext)
	return nil
}

func IsReference(key []byte) bool { return strings.HasPrefix(string(key), referencePrefix) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
