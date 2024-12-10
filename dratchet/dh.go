package dratchet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type DHPair interface {
	PrivateKey() Key
	PublicKey() Key
}

// Creates a new Diffie-Hellman key pair
func GenerateDH() (DHPair, error) {
	var privKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
		return dhPair{}, fmt.Errorf("couldn't generate privKey: %s", err)
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return dhPair{
		privateKey: privKey[:],
		publicKey:  pubKey[:],
	}, nil
}

// Calculates shared secret using Diffie-Hellman
func DH(dhPair DHPair, dhPub Key) (Key, error) {
	var (
		privKey [32]byte
		pubKey  [32]byte
	)
	if len(dhPair.PrivateKey()) != 32 {
		return nil, fmt.Errorf("Invalid private key length: %d", len(dhPair.PrivateKey()))
	}

	if len(dhPub) != 32 {
		return nil, fmt.Errorf("Invalid private key length: %d", len(dhPair.PrivateKey()))
	}

	copy(privKey[:], dhPair.PrivateKey()[:32])
	copy(pubKey[:], dhPub[:32])

	return curve25519.X25519(privKey[:], pubKey[:])
}

// Generates a pair 32-byte root key, 32-byte chain key
func KdfRK(rk, dhOut Key) (Key, Key) {
	var (
		r   = hkdf.New(sha256.New, dhOut, rk, []byte("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL"))
		buf = make([]byte, 64)
	)

	_, _ = io.ReadFull(r, buf)

	rootKey := make(Key, 32)
	chainKey := make(Key, 32)

	copy(rootKey[:], buf[:32])
	copy(chainKey[:], buf[32:])
	return rootKey, chainKey
}

// Generates a pair 32-byte chain key, 32-byte message key
func KdfCK(ck Key) (Key, Key) {
	ckInput := []byte{0x01}
	mkInput := []byte{0x02}

	chainKey := make(Key, 32)
	msgKey := make(Key, 32)

	h := hmac.New(sha256.New, ck[:])

	h.Write(ckInput)
	copy(chainKey[:], h.Sum(nil))
	h.Reset()

	h.Write(mkInput)
	copy(msgKey[:], h.Sum(nil))

	return chainKey, msgKey
}

// AES-256-CTR encryption
func Encrypt(mk Key, plaintext, ad []byte) ([]byte, error) {
	encKey, authKey, iv := deriveEncKeys(mk)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext, iv[:])

	var (
		block, _ = aes.NewCipher(encKey[:])
		stream   = cipher.NewCTR(block, iv[:])
	)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return append(ciphertext, getAuthTag(authKey[:], ciphertext, ad)...), nil
}

// Returns the AEAD decryption of ciphertext
func Decrypt(mk Key, authCiphertext, ad []byte) ([]byte, error) {
	var (
		l          = len(authCiphertext)
		ciphertext = authCiphertext[:l-sha256.Size]
		signature  = authCiphertext[l-sha256.Size:]
	)

	// Check the signature
	encKey, authKey, _ := deriveEncKeys(mk)
	if s := getAuthTag(authKey[:], ciphertext, ad); !bytes.Equal(s, signature) {
		return nil, fmt.Errorf("authentication failed")
	}

	// Decrypt
	var (
		block, _  = aes.NewCipher(encKey[:])
		stream    = cipher.NewCTR(block, ciphertext[:aes.BlockSize])
		plaintext = make([]byte, len(ciphertext[aes.BlockSize:]))
	)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}

// Derive keys for message encryption and decryption. Returns (encKey, authKey, iv, err).
func deriveEncKeys(mk Key) (Key, Key, [16]byte) {
	salt := make([]byte, 32)
	var (
		r   = hkdf.New(sha256.New, mk[:], salt, []byte("pcwSByyx2CRdryCffXJwy7xgVZWtW5Sh"))
		buf = make([]byte, 80)
	)

	_, _ = io.ReadFull(r, buf)

	var encKey Key = make(Key, 32)
	var authKey Key = make(Key, 32)
	var iv [16]byte

	copy(encKey[:], buf[0:32])
	copy(authKey[:], buf[32:64])
	copy(iv[:], buf[64:80])

	return encKey, authKey, iv
}

func getAuthTag(authKey, ciphertext, ad []byte) []byte {
	h := hmac.New(sha256.New, authKey)
	_, _ = h.Write(ad)
	_, _ = h.Write(ciphertext)
	return h.Sum(nil)
}

// Implements DHPair
type dhPair struct {
	privateKey Key
	publicKey  Key
}

func (p dhPair) PrivateKey() Key {
	return p.privateKey
}

func (p dhPair) PublicKey() Key {
	return p.publicKey
}
