package main

import (
	"fmt"
	"signal/internal/doubleratchet"
	"time"
)

func main() {
	state := doubleratchet.State{}

	mk := []byte("keyyy")
	plaintext := []byte("Message in a Bottle :)")
	associatedData := []byte("data")

	now := time.Now()
	encrypted, err := state.Encrypt(mk, plaintext, associatedData)
	fmt.Printf("Time taken to encrypt: %dms\n", time.Since(now).Microseconds())
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted: %s\n", string(encrypted))
	fmt.Printf("Length: %d\n", len(encrypted))

	//mk = []byte("no-keyyy")
	now = time.Now()
	decrypted, err := state.Decrypt(mk, encrypted, associatedData)
	fmt.Printf("Time taken to decrypt: %dms\n", time.Since(now).Microseconds())
	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))
}
