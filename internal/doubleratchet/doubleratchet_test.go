package doubleratchet

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

type message struct {
	header     *RatchetHeader
	ciphertext []byte
	plaintext  []byte
}

type testState struct {
	bob               *State
	ikBob             *ecdh.PublicKey
	alice             *State
	ikAlice           *ecdh.PublicKey
	aliceSentMessages []*message
	bobSentMessages   []*message
	t                 *testing.T
}

func TestDoubleRatchetIntegrationSimple(t *testing.T) {
	s := initTest(t, []byte("very secret"))

	s.aliceSendMessages("Hello Bob", "Message in a Bottle :)")
	s.bobReceiveMessages(2)

	// Fail Case 1: Alice sends a message with N=3000 (MaxSkip=1000)
	s.aliceSendMessages("this should not be received")
	s.aliceSentMessages[2].header.N = 3000
	err := s.bobReceiveMessageUnsafe(s.aliceSentMessages[2])
	if err == nil {
		t.Fatal("Should not be able to decrypt message with N=3000")
	} else {
		t.Log("Correctly failed to decrypt message with N=3000", err.Error())
	}

	// Fail Case 2: Alice sends a message with N=10
	// Bobs state should be backed up and restored so following messages can be decrypted
	s.aliceSendMessages("this should not be received")
	s.aliceSentMessages[2].header.N = 10
	err = s.bobReceiveMessageUnsafe(s.aliceSentMessages[2])
	if err == nil {
		t.Fatal("Should not be able to decrypt message")
	} else {
		t.Log("Correctly failed to decrypt message", err.Error())
	}

	s.bobSendMessages("Hello Alice", "Another Message in a Bottle :)")

	s.aliceReceiveMessages(2)
	s.bobReceiveMessages(1)

	s.bobSendMessages("blabla")
	s.aliceReceiveMessages(3)
	s.aliceReceiveMessages(1)
}

func (s *testState) bobSendMessages(messages ...string) {
	for _, msg := range messages {
		s.bobSentMessages = append(s.bobSentMessages, sendMessage(s.t, s.bob, msg))
	}
}

func (s *testState) aliceSendMessages(messages ...string) {
	for _, msg := range messages {
		s.aliceSentMessages = append(s.aliceSentMessages, sendMessage(s.t, s.alice, msg))
	}
}

func (s *testState) bobReceiveMessages(numbers ...int) {
	for _, n := range numbers {
		_ = receiveMessage(s.t, s.bob, s.aliceSentMessages, n)
	}
}

func (s *testState) aliceReceiveMessages(numbers ...int) {
	for _, n := range numbers {
		_ = receiveMessage(s.t, s.alice, s.bobSentMessages, n)
	}
}

func (s *testState) bobReceiveMessageUnsafe(message *message) error {
	ad := []byte("associatedData")
	_, err := s.bob.RatchetDecrypt(message.header, message.ciphertext, ad)
	if err != nil {
		return err
	}

	return nil
}

func initTest(t *testing.T, sharedSecret []byte) (s *testState) {
	ikBob, err := GenerateDH()
	if err != nil {
		t.Fatal("Could not generate DH key pair", err.Error())
	}
	ikAlice, err := GenerateDH()
	if err != nil {
		t.Fatal("Could not generate DH key pair", err.Error())
	}

	s = &testState{
		t: t,
	}

	var err error

	//s.bob = RatchetInitBob(sharedSecret, bobKeyPair)
	s.bob, err = New(sharedSecret, nil)
	if err != nil {
		t.Fatal("Could not create Bob Doubleratchet", err.Error())
	}

	s.alice, err = RatchetInitAlice(sharedSecret, s.bob.GetPublicKey())
	if err != nil {
		t.Fatal("Could not create Alice Doubleratchet", err.Error())
	}
	return
}

func sendMessage(t *testing.T, s *State, msg string) *message {
	//fmt.Println("################## sendMessages ##################")

	plaintext := []byte(msg)
	ad := []byte("associatedData")

	header, ciphertext, err := s.RatchetEncrypt(plaintext, ad)
	if err != nil {
		t.Fatal("Could not encrypt message", err.Error())
	}

	//fmt.Printf("################## ----------- ##################\n\n\n")
	return &message{
		plaintext:  plaintext,
		ciphertext: ciphertext,
		header:     header,
	}
}

func receiveMessage(t *testing.T, s *State, messages []*message, n int) []byte {
	if len(messages) < n && messages[n-1] == nil {
		t.Fatal("Message not found")
	}
	message := messages[n-1]
	messages[n-1] = nil
	//fmt.Printf("################## receiveMessage %d ##################\n", n)

	ad := []byte("associatedData")
	decryptedPlaintext, err := s.RatchetDecrypt(message.header, message.ciphertext, ad)
	if err != nil {
		t.Fatal("Could not decrypt message:", err.Error())
	}

	if !bytes.Equal(message.plaintext, decryptedPlaintext) {
		t.Fatal("Did not receive the correct plaintext")
	} else {
		t.Logf("Successfully decrypted message: %d", n)
	}

	//fmt.Printf("################## -------------- ##################\n\n\n")
	return decryptedPlaintext
}
