package session

import (
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
		localIdentityKey:  ikBob.PublicKey(),
		remoteIdentityKey: ikAlice.PublicKey(),
	}

	// AD in alice's session
	adAlice := &associatedData{
		localIdentityKey:  ikAlice.PublicKey(),
		remoteIdentityKey: ikBob.PublicKey(),
	}

	// alice sends bob a message with her encoded AD
	encoded := adAlice.encode()

	// bob decodes the received AD
	decodedAd := &associatedData{}
	// when decoding, the local and remote keys should be swapped
	err = decodedAd.decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode associated data: %v", err)
	}

	if !adBob.equal(*decodedAd) {
		t.Fatalf("Decoded keys do not match original keys")
	}
}

func TestAssociatedDataEqual(t *testing.T) {
	curve := ecdh.X25519()
	localKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate local key: %v", err)
	}
	remoteKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate remote key: %v", err)
	}

	ad1 := &associatedData{
		localIdentityKey:  localKey.PublicKey(),
		remoteIdentityKey: remoteKey.PublicKey(),
	}

	ad2 := &associatedData{
		localIdentityKey:  localKey.PublicKey(),
		remoteIdentityKey: remoteKey.PublicKey(),
	}

	if !ad1.equal(*ad2) {
		t.Fatalf("Expected associatedData instances to be equal")
	}
}
