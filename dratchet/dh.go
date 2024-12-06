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

// creates a new Diffie-Hellman key pair.
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

// returns the output from the Diffie-Hellman calculation between
// the private key from the DH key pair dhPair and the DH public key dbPub.
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

// returns a pair (32-byte root key, 32-byte chain key) as the output of applying
// a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dhOut.
func KdfRK(rk, dhOut Key) (Key, Key, Key) {
	var (
		r   = hkdf.New(sha256.New, dhOut, rk, []byte("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL"))
		buf = make([]byte, 96)
	)

	// The only error here is an entropy limit which won't be reached for such a short buffer.
	_, _ = io.ReadFull(r, buf)

	rootKey := make(Key, 32)
	headerKey := make(Key, 32)
	chainKey := make(Key, 32)

	copy(rootKey[:], buf[:32])
	copy(chainKey[:], buf[32:64])
	copy(headerKey[:], buf[64:96])
	return rootKey, chainKey, headerKey
}

// Returns a pair (32-byte chain key, 32-byte message key) as the output of applying
// a KDF keyed by a 32-byte chain key ck to some constant.
func KdfCK(ck Key) (Key, Key) {
	const (
		ckInput = 15
		mkInput = 16
	)

	chainKey := make(Key, 32)
	msgKey := make(Key, 32)

	h := hmac.New(sha256.New, ck[:])

	_, _ = h.Write([]byte{ckInput})
	copy(chainKey[:], h.Sum(nil))
	h.Reset()

	_, _ = h.Write([]byte{mkInput})
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

// Decrypt returns the AEAD decryption of ciphertext with message key mk.
func Decrypt(mk Key, authCiphertext, ad []byte) ([]byte, error) {
	var (
		l          = len(authCiphertext)
		ciphertext = authCiphertext[:l-sha256.Size]
		signature  = authCiphertext[l-sha256.Size:]
	)

	// Check the signature.
	encKey, authKey, _ := deriveEncKeys(mk)
	if s := getAuthTag(authKey[:], ciphertext, ad); !bytes.Equal(s, signature) {
		return nil, fmt.Errorf("authentication failed")
	}

	// Decrypt.
	var (
		block, _  = aes.NewCipher(encKey[:])
		stream    = cipher.NewCTR(block, ciphertext[:aes.BlockSize])
		plaintext = make([]byte, len(ciphertext[aes.BlockSize:]))
	)
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	return plaintext, nil
}

// derive keys for message encryption and decryption. Returns (encKey, authKey, iv, err).
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
