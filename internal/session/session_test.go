package session

/*
func TestSessionIntegration(t *testing.T) {
	sharedSecret := []byte("very secret")
	bob := initializeSession(t, "bob", sharedSecret, nil)
	alice := initializeSession(t, "alice", sharedSecret, bob.GetPublicKey())

	bobM1 := createMessage(t, bob, "Hello Alice, this is Bob")
	receiveAndCompareMessage(t, alice, bobM1, "Hello Alice, this is Bob")

	//aliceM1 := createMessage(t, alice, "Hello Bob, this is Alice")
	//receiveAndCompareMessage(t, bob, aliceM1, "Hello Bob, this is Alice")
}

// Helper function to initialize a session
func initializeSession(t *testing.T, user string, sharedSecret []byte, publicKey *ecdh.PublicKey) *Session {
	session, err := NewSession(user, sharedSecret, publicKey)
	if err != nil {
		t.Fatalf("Could not create session: %v", err)
	}
	return session
}

func receiveAndCompareMessage(t *testing.T, session *Session, message *types.Message, expectedPlaintext string) {
	plaintext, err := session.DecryptMessage(message)
	if err != nil {
		t.Fatalf("Could not decrypt message: %v", err)
	}
	if !bytes.Equal(plaintext, []byte(expectedPlaintext)) {
		t.Fatalf("Decrypted plaintext does not match expected plaintext")
	}
	t.Logf("Successfully decrypted message: %s", plaintext)
}

func createMessage(t *testing.T, session *Session, plaintext string) *types.Message {
	message, err := session.CreateEncryptedMessage([]byte(plaintext))
	if err != nil {
		t.Fatalf("Could not create message: %v", err)
	}
	return message
}
*/
