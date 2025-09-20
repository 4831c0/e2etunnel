package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// X25519Keypair holds an X25519 private/public key.
type X25519Keypair struct {
	Private [32]byte // keep secret
	Public  [32]byte
}

// GenerateX25519Keypair generates a new X25519 keypair.
func GenerateX25519Keypair() (*X25519Keypair, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, err
	}
	// X25519 scalar clamping per RFC7748: library X25519 will handle internally
	// but keeping the raw scalar is fine for X25519() usage.
	var pub [32]byte
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(pub[:], out)
	return &X25519Keypair{Private: priv, Public: pub}, nil
}

// deriveKey derives a 32-byte symmetric key from an X25519 shared secret and optional info.
func deriveKey(sharedSecret []byte, info []byte) ([]byte, error) {
	hk := hkdf.New(sha256.New, sharedSecret, nil, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	return key, nil
}

// X25519Encrypt encrypts plaintext for recipientPub using an ephemeral X25519 key.
// Returns ciphertext: 0x01 || ephPub(32) || nonce(24) || aeadCiphertext
func X25519Encrypt(recipientPub [32]byte, plaintext, aad []byte) ([]byte, error) {
	// generate ephemeral keypair
	eph, err := GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}

	// shared secret = X25519(eph.priv, recipientPub)
	secret, err := curve25519.X25519(eph.Private[:], recipientPub[:])
	if err != nil {
		return nil, err
	}

	// optional context info for HKDF (version + pubkeys)
	info := make([]byte, 1+32+32)
	info[0] = 0x01 // version byte for KDF context
	copy(info[1:33], eph.Public[:])
	copy(info[33:], recipientPub[:])

	symmKey, err := deriveKey(secret, info)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(symmKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 1+32+len(nonce)+len(ct))
	out[0] = 0x01
	copy(out[1:33], eph.Public[:])
	copy(out[33:33+len(nonce)], nonce)
	copy(out[33+len(nonce):], ct)
	return out, nil
}

// X25519Decrypt decrypts ciphertext with recipient private key.
// Expects format produced by X25519Encrypt. Returns plaintext and any associated data must match during encryption.
func X25519Decrypt(recipientPriv [32]byte, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < 1+32+chacha20poly1305.NonceSizeX {
		return nil, errors.New("ciphertext too short")
	}
	if ciphertext[0] != 0x01 {
		return nil, errors.New("unsupported version")
	}
	ephPub := [32]byte{}
	copy(ephPub[:], ciphertext[1:33])
	nonce := ciphertext[33 : 33+chacha20poly1305.NonceSizeX]
	ct := ciphertext[33+chacha20poly1305.NonceSizeX:]

	// shared secret = X25519(recipientPriv, ephPub)
	secret, err := curve25519.X25519(recipientPriv[:], ephPub[:])
	if err != nil {
		return nil, err
	}

	info := make([]byte, 1+32+32)
	info[0] = 0x01
	copy(info[1:33], ephPub[:])
	// recipient public key is derived from recipientPriv
	var recipientPub [32]byte
	pubBytes, err := curve25519.X25519(recipientPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(recipientPub[:], pubBytes)
	copy(info[33:], recipientPub[:])

	symmKey, err := deriveKey(secret, info)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(symmKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// ExportPublic returns the public key bytes (32 bytes).
func (k *X25519Keypair) ExportPublic() []byte {
	out := make([]byte, 32)
	copy(out, k.Public[:])
	return out
}

// ExportPrivate returns the private key bytes (32 bytes). Keep secret.
func (k *X25519Keypair) ExportPrivate() []byte {
	out := make([]byte, 32)
	copy(out, k.Private[:])
	return out
}

// ImportPrivate loads a 32-byte private key into X25519Keypair and computes the public key.
func ImportPrivate(privBytes []byte) (*X25519Keypair, error) {
	if len(privBytes) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	var priv [32]byte
	copy(priv[:], privBytes)
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	return &X25519Keypair{Private: priv, Public: pub}, nil
}

// Helper: deterministic short ID (optional)
func shortID(pub [32]byte) uint64 {
	return binary.LittleEndian.Uint64(pub[:8])
}
