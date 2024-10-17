package doubleratchet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptAndDecryptIntegration(t *testing.T) {
	mk := []byte("keyyy")
	plaintext := []byte("Message in a Bottle :)")
	associatedData := []byte("associatedData")

	encrypted, err := Encrypt(mk, plaintext, associatedData)
	if err != nil {
		t.Fatal("Encrypt failed:", err.Error())
	}

	decrypted, err := Decrypt(mk, encrypted, associatedData)
	if err != nil {
		t.Fatal("Decrypt failed:", err.Error())
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("Result is not same as Plaintext")
	}
}

func TestConcatAndParseIntegration(t *testing.T) {
	dhKP, err := GenerateDH()
	if err != nil {
		t.Fatal("GenerateDH failed:", err.Error())
	}
	dh := dhKP.PublicKey()

	header := &MessageHeader{
		DH: dh,
		PN: 13,
		N:  3,
	}
	associatedData := []byte("associatedData")

	concatinated, err := Concat(associatedData, header)
	if err != nil {
		t.Fatal("Concat failed:", err.Error())
	}

	parsedHeader, parsedAd, err := Parse(concatinated)
	if err != nil {
		t.Fatal("Parse failed:", err.Error())
	}

	if !header.Equals(parsedHeader) {
		t.Fatal("Parsed header is not same as header")
	}
	if !bytes.Equal(associatedData, parsedAd) {
		t.Fatal("Parsed associatedData is not same as associatedData")
	}
}

func TestKDFChainKey(t *testing.T) {
	// Create a 32-byte key
	key := make([]byte, 32)

	// Fill the byte slice with random data
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal("generating chainKey failed:", err.Error())
	}
	if len(key) != 32 {
		t.Fatal("original chainKey length isn't 32, Actual:", len(key))
	}

	newChainKey, messageKey := KDFChainKey(key)
	if len(newChainKey) != 32 {
		t.Fatal("new chainKey length isn't 32, Actual:", len(newChainKey))
	}
	if len(messageKey) != 32 {
		t.Fatal("message key length isn't 32, Actual:", len(messageKey))
	}
}

func TestKDFRootKey(t *testing.T) {
	bobDHPrivateKey, err := GenerateDH()
	if err != nil {
		t.Fatal("GenerateDH failed:", err.Error())
	}
	bobDHPublicKey := bobDHPrivateKey.PublicKey()

	// Create a 32-byte key
	secretKey := make([]byte, 32)

	// Fill the byte slice with random data
	_, err = rand.Read(secretKey)
	if err != nil {
		t.Fatal("generating chainKey failed:", err.Error())
	}
	if len(secretKey) != 32 {
		t.Fatal("original chainKey length isn't 32, Actual:", len(secretKey))
	}

	aliceDHRootKey, err := GenerateDH()
	if err != nil {
		t.Fatal("GenerateDH failed:", err.Error())
	}

	dhOut, err := DH(aliceDHRootKey, bobDHPublicKey)
	if err != nil {
		t.Fatal("DH failed:", err.Error())
	}
	rootKey, chainKey, err := KDFRootKey(secretKey, dhOut)
	if err != nil {
		t.Fatal("KDFRootKey failed:", err.Error())
	}
	if len(rootKey) != 32 {
		t.Fatal("rootKey length isn't 32, Actual:", len(rootKey))
	}
	if len(chainKey) != 32 {
		t.Fatal("message key length isn't 32, Actual:", len(chainKey))
	}
}

func TestPKCS7PaddingIntegration(t *testing.T) {
	blockSize := 16
	data := []byte("abcdefgh")

	padded := padPKCS7(data, blockSize)
	if len(padded)%blockSize != 0 {
		t.Fatal("padded data is not a multiple of the block size")
	}

	unpadded, err := unpadPKCS7(padded)
	if err != nil {
		t.Fatal("unpadPKCS7 failed:", err.Error())
	}

	if !bytes.Equal(unpadded, data) {
		t.Fatal("unpadPKCS7 is not same as data")
	}
}
