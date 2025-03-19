package session

import (
	"bytes"
	"crypto/ecdh"
	"signal/internal/doubleratchet"
	"testing"
)

// mkSkippedKey is a key for the map of skipped message keys
type mkSkippedKey struct {
	DH string // DH Ratchet public key
	N  int    // Message number
}

// Session State variables required for a session
type Session struct {
	DHs       *ecdh.PrivateKey        // DH Ratchet key pair (sending)
	DHr       *ecdh.PublicKey         // DH Ratchet public key (received)
	RK        []byte                  // Root key
	CKs       []byte                  // Chain key (sending)
	CKr       []byte                  // Chain key (receiving)
	Ns, Nr    int                     // Message numbers for sending and receiving
	PN        int                     // Number of messages in the previous sending chain
	MKSkipped map[mkSkippedKey][]byte // Skipped message keys
}

func (s *Session) NewSession(sharedSecret []byte) (*Session, error) {
	keyPair, err := doubleratchet.GenerateDH()
	if err != nil {
		return nil, err
	}
	return &Session{
		DHs:       keyPair,
		DHr:       nil,
		RK:        sharedSecret,
		CKs:       nil,
		CKr:       nil,
		Ns:        0,
		Nr:        0,
		PN:        0,
		MKSkipped: make(map[mkSkippedKey][]byte),
	}, nil
}

func (s *Session) sendMessage(msg string) *message {
	plaintext := []byte(msg)
	ad := []byte("associatedData")

	header, ciphertext, err := s.RatchetEncrypt(plaintext, ad)
	if err != nil {
		t.Fatal("Could not encrypt message", err.Error())
	}

	return &message{
		plaintext:  plaintext,
		ciphertext: ciphertext,
		header:     header,
	}
}

func receiveMessage(t *testing.T, s *State, messages []*message, n int) []byte {
	message := messages[n-1]
	messages[n-1] = nil
	//fmt.Printf("################## receiveMessage %d ##################\n", n)

	ad := []byte("associatedData")
	decryptedPlaintext, err := s.RatchetDecrypt(message.header, message.ciphertext, ad)
	if err != nil {
		t.Fatal("Could not decrypt message", err.Error())
	}

	if !bytes.Equal(message.plaintext, decryptedPlaintext) {
		t.Fatal("Did not receive the correct plaintext")
	} else {
		t.Logf("Successfully decrypted message: %d", n)
	}

	//fmt.Printf("################## -------------- ##################\n\n\n")
	return decryptedPlaintext
}
