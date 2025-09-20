package main

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = chacha20poly1305.KeySize

const NonceSize = chacha20poly1305.NonceSize

// ChaChaGenerateNonce returns a cryptographically-random 12-byte nonce.
func ChaChaGenerateNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	_, err := rand.Read(n)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// ChaChaSeal encrypts plaintext with key and associatedData.
// It returns a single byte slice containing nonce || ciphertext (ciphertext includes tag).
// nonce must be NonceSize bytes; if nil, a random nonce will be generated.
func ChaChaSeal(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	if nonce == nil {
		nonce, err = ChaChaGenerateNonce()
		if err != nil {
			return nil, err
		}
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("invalid nonce size")
	}

	ct := aead.Seal(nil, nonce, plaintext, associatedData)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// ChaChaOpen decrypts sealed (nonce||ciphertext) with key and associatedData.
// Returns plaintext on success.
func ChaChaOpen(key, sealed, associatedData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size")
	}
	if len(sealed) < NonceSize+chacha20poly1305.Overhead {
		return nil, errors.New("sealed data too short")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := sealed[:NonceSize]
	ct := sealed[NonceSize:]
	plain, err := aead.Open(nil, nonce, ct, associatedData)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
