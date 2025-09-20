package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"crypto/mlkem"
)

// MlKemKeyPair holds an ML-KEM key pair.
type MlKemKeyPair struct {
	Public  []byte
	Private []byte
}

// GenerateMlKemKeyPair1024 generates a new ML-KEM-1024 key pair and returns the
// public and private keys as encoded bytes.
func GenerateMlKemKeyPair1024() (*MlKemKeyPair, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	pub := dk.EncapsulationKey().Bytes()
	priv := dk.Bytes()
	return &MlKemKeyPair{Public: pub, Private: priv}, nil
}

// MlEncrypt1024 takes a public encapsulation key (encoded bytes) and returns
// (sharedKey, ciphertext).
func mlEncrypt1024(publicKey []byte) (sharedKey, ciphertext []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey1024(publicKey)
	if err != nil {
		return nil, nil, err
	}
	sk, ct := ek.Encapsulate()
	return sk, ct, nil
}

// MlDecrypt1024 takes a private decapsulation key (encoded seed bytes) and a
// ciphertext and returns the shared key. Returns an error if decapsulation fails.
func mlDecrypt1024(privateKey []byte, ciphertext []byte) (sharedKey []byte, err error) {
	if len(privateKey) != mlkem.SeedSize {
		return nil, errors.New("invalid private key length")
	}
	dk, err := mlkem.NewDecapsulationKey1024(privateKey)
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ciphertext)
}

// EncryptWithMlKem encrypts plaintext using the recipient's ML-KEM public key.
// Returns: ciphertext (nonce||gcmCiphertext), encapsulation (to send to recipient).
func EncryptWithMlKem(recipientPub []byte, plaintext []byte) (ciphertext []byte, encapsulation []byte, err error) {
	// 1) ML-KEM encapsulation
	sharedKey, encapsulation, err := mlEncrypt1024(recipientPub)
	if err != nil {
		return nil, nil, err
	}

	sym := sha256.Sum256(sharedKey)

	block, err := aes.NewCipher(sym[:])
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ct := aesgcm.Seal(nil, nonce, plaintext, nil)

	ciphertext = append(nonce, ct...)
	return ciphertext, encapsulation, nil
}

// DecryptWithMlKem decrypts ciphertext using the recipient's ML-KEM private key.
// Inputs: privateSeed (the private key bytes you store), encapsulation (received from sender),
// ciphertext (nonce||gcmCiphertext).
func DecryptWithMlKem(privateSeed []byte, encapsulation []byte, ciphertext []byte) (plaintext []byte, err error) {
	sharedKey, err := mlDecrypt1024(privateSeed, encapsulation)
	if err != nil {
		return nil, err
	}

	sym := sha256.Sum256(sharedKey)

	block, err := aes.NewCipher(sym[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	plaintext, err = aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
