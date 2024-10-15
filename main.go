package main

import (
	"fmt"
	"signal/internal/doubleratchet"
)

func main() {
	sharedSecret := []byte("very secret")

	bobKeyPair, err := doubleratchet.GenerateDH()
	if err != nil {
		panic(err)
	}

	bob, err := doubleratchet.RatchetInitBob(sharedSecret, bobKeyPair)
	if err != nil {
		panic(err)
	}

	alice, err := doubleratchet.RatchetInitAlice(sharedSecret, bobKeyPair.PublicKey())
	if err != nil {
		panic(err)
	}

	plaintext := []byte("Message in a Bottle :)")
	ad := []byte("associatedData")

	header, ciphertext, err := alice.RatchetEncrypt(plaintext, ad)
	if err != nil {
		panic(err)
	}

	decryptedPlaintext, err := bob.RatchetDecrypt(header, ciphertext, ad)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(decryptedPlaintext))
}
