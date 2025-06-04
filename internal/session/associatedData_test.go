package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestAssociatedDataEncodeDecode(t *testing.T) {
	curve := ecdh.X25519()
	ikBob, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate local key: %v", err)
	}
	ikAlice, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate remote key: %v", err)
	}

	// AD in bob's session
	adBob := &associatedData{
		localUsername:     "bob",
		localIdentityKey:  *ikBob.PublicKey(),
		remoteUsername:    "alice",
		remoteIdentityKey: *ikAlice.PublicKey(),
	}

	// AD in alice's session
	adAlice := &associatedData{
		localUsername:     "alice",
		localIdentityKey:  *ikAlice.PublicKey(),
		remoteUsername:    "bob",
		remoteIdentityKey: *ikBob.PublicKey(),
	}

	// alice sends bob a message with her encoded AD
	encoded1 := adAlice.encodeForEncryption()
	encoded2 := adBob.encodeForDecryption()

	if !bytes.Equal(encoded1, encoded2) {
		t.Fatalf("Decoded for encryption and decoded for Decryption do not match")
	}
}
