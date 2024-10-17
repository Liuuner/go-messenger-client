package doubleratchet

import (
	"bytes"
	"testing"
)

func TestDoubleRatchetIntegration(t *testing.T) {
	sharedSecret := []byte("very secret")

	bobKeyPair, err := GenerateDH()
	if err != nil {
		t.Fatal("Could not generate KeyPair", err.Error())
	}

	bob := RatchetInitBob(sharedSecret, bobKeyPair)

	alice, err := RatchetInitAlice(sharedSecret, bobKeyPair.PublicKey())
	if err != nil {
		t.Fatal("Could not init Alice", err.Error())
	}

	bob.DHr = alice.DHs.PublicKey()

	plaintext := []byte("Message in a Bottle :)")
	ad := []byte("associatedData")

	header, ciphertext, err := alice.RatchetEncrypt(plaintext, ad)
	if err != nil {
		t.Fatal("Could not encrypt message", err.Error())
	}

	decryptedPlaintext, err := bob.RatchetDecrypt(header, ciphertext, ad)
	if err != nil {
		t.Fatal("Could not decrypt message", err.Error())
	}

	if !bytes.Equal(plaintext, decryptedPlaintext) {
		t.Fatal("Decrypted plaintext doesn't match original plaintext")
	}
}
