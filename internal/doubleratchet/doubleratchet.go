// Package doubleratchet is implemented as specified in https://signal.org/docs/specifications/doubleratchet/#external-functions
package doubleratchet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type State struct {
	// State variables
	DHs       *ecdh.PrivateKey          // DH Ratchet key pair (sending)
	DHr       *ecdh.PublicKey           // DH Ratchet public key (received)
	RK        []byte                    // Root key
	CKs       []byte                    // Chain key (sending)
	CKr       []byte                    // Chain key (receiving)
	Ns, Nr    int                       // Message numbers for sending and receiving
	PN        int                       // Number of messages in the previous sending chain
	MKSkipped map[string]map[int][]byte // Skipped message keys
}

// GenerateDH returns a new Diffie-Hellman key pair
func (s *State) GenerateDH() (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	pk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// DH returns the output from the Diffie-Hellman calculation between the private key from the DH key pair dhPair and the DH public key dhPub.
func (s *State) DH(dhPair *ecdh.PrivateKey, dhPub *ecdh.PublicKey) ([]byte, error) {
	result, err := dhPair.ECDH(dhPub)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// KDFRootKey returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dhOut
func (s *State) KDFRootKey(rk, dhOut []byte) (rootKey, chainKey []byte, err error) {
	// Underlying hash function for HMAC.
	hash := sha512.New

	// Cryptographically secure master secret.
	secret := dhOut

	// Salt
	salt := rk

	// Non-secret context info
	info := []byte("doubleratchet.KDFRootKey")

	kdf := hkdf.New(hash, secret, salt, info)

	// Read two Keys
	var keys [][]byte
	for range 2 {
		key := make([]byte, 32)
		if _, err := io.ReadFull(kdf, key); err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
	}

	return keys[0], keys[1], nil
}

// KDFChainKey returns a pair (32-byte chain key, 32-byte message key) as the output of applying a KDF keyed by a 32-byte chain key ck to some constant
func (s *State) KDFChainKey(ck []byte) (newChainKey, messageKey []byte) {
	// Underlying hash function for HMAC.
	hash := sha512.New

	// Derive next chain key
	constant := []byte{0x03}
	hmacChainKey := hmac.New(hash, ck)
	hmacChainKey.Write(constant)
	newChainKey = hmacChainKey.Sum(nil)

	// Derive message key
	constant = []byte{0x0D}
	hmacMessageKey := hmac.New(hash, ck)
	hmacMessageKey.Write(constant)
	messageKey = hmacMessageKey.Sum(nil)

	return newChainKey, messageKey
}

// Encrypt implements the encryption algorithm with AEAD based on AES-256-CBC + HMAC.
// Encrypt returns an AEAD encryption of plaintext with message key mk. The associatedData is authenticated but is not included in the ciphertext.
func (s *State) Encrypt(mk, plaintext, associatedData []byte) ([]byte, error) {
	keySize := 32
	authKeySize := 32
	ivSize := 16 // IV size for AES-CBC
	outputLength := keySize + authKeySize + ivSize
	hash := sha512.New

	// Step 1: Derive keys and IV using HKDF
	info := []byte("doubleratchet.Encrypt")
	salt := make([]byte, hash().Size())
	kdf := hkdf.New(hash, mk, salt, info)

	keyMaterial := make([]byte, outputLength)
	if _, err := io.ReadFull(kdf, keyMaterial); err != nil {
		return nil, err
	}

	// separate Key Material into the parts
	encKey := keyMaterial[:keySize]
	authKey := keyMaterial[keySize : keySize+authKeySize]
	iv := keyMaterial[keySize+authKeySize:]

	// Step 2: Encrypt plaintext using AES-256 in CBC mode
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	block.BlockSize()

	fmt.Printf("PaddingBytes:%d\n", block.BlockSize())

	paddedPlaintext := padPKCS7(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(paddedPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Step 3: Compute HMAC
	mac := hmac.New(hash, authKey)
	mac.Write(associatedData)
	mac.Write(ciphertext)
	hmacSum := mac.Sum(nil)

	// Step 4: Return ciphertext with HMAC appended
	return append(ciphertext, hmacSum...), nil
}

// PKCS7 padding for AES CBC mode
func padPKCS7(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// Unpad PKCS7
func unpadPKCS7(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	padLen := int(data[length-1])
	if padLen > length {
		return nil, errors.New("invalid padding")
	}
	return data[:length-padLen], nil
}

// Decrypt implements the decryption algorithm with AEAD based on AES-256-CBC + HMAC.
// Returns the AEAD decryption of ciphertext with message key mk.
// If authentication fails, an error is returned.
func (s *State) Decrypt(mk, ciphertext, associatedData []byte) ([]byte, error) {
	keySize := 32
	authKeySize := 32
	ivSize := 16 // IV size for AES-CBC
	hash := sha512.New

	// Step 1: Separate the HMAC from the ciphertext
	if len(ciphertext) < keySize+authKeySize+ivSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the HMAC from the end of the ciphertext
	hmacSum := ciphertext[len(ciphertext)-sha512.Size:]
	ciphertextWithoutHMAC := ciphertext[:len(ciphertext)-sha512.Size]

	// Step 2: Derive keys and IV using HKDF
	info := []byte("doubleratchet.Encrypt") // has to be the same info as with encrypt
	salt := make([]byte, hash().Size())
	kdf := hkdf.New(hash, mk, salt, info)

	keyMaterial := make([]byte, keySize+authKeySize+ivSize)
	if _, err := io.ReadFull(kdf, keyMaterial); err != nil {
		return nil, err
	}

	// Separate Key Material into the parts
	encKey := keyMaterial[:keySize]
	authKey := keyMaterial[keySize : keySize+authKeySize]
	iv := keyMaterial[keySize+authKeySize:]

	// Step 3: Verify HMAC
	mac := hmac.New(hash, authKey)
	mac.Write(associatedData)
	mac.Write(ciphertextWithoutHMAC)
	expectedHMAC := mac.Sum(nil)

	if !hmac.Equal(hmacSum, expectedHMAC) {
		return nil, errors.New("authentication failed")
	}

	// Step 4: Decrypt ciphertext using AES-256 in CBC mode
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	paddedPlaintext := make([]byte, len(ciphertextWithoutHMAC))
	mode.CryptBlocks(paddedPlaintext, ciphertextWithoutHMAC)

	// Step 5: Unpad the plaintext
	plaintext, err := unpadPKCS7(paddedPlaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (s *State) CreateHeader(dhPair *ecdh.PrivateKey, pn, n int) *MessageHeader {
	return nil
}

func (s *State) Concat(ad []byte, header *MessageHeader) ([]byte, error) {
	return nil, nil
}
