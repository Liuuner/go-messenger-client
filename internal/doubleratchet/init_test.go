package doubleratchet

import (
	"bytes"
	"fmt"
	"testing"
)

type message struct {
	header     *MessageHeader
	ciphertext []byte
	plaintext  []byte
}

type testState struct {
	bob   *State
	alice *State
}

func TestDoubleRatchetIntegrationSimple(t *testing.T) {
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

	var aliceSentMessages []*message
	var bobSentMessages []*message

	// Alice Send Message 1
	aliceSentMessages = append(aliceSentMessages, sendMessage(t, alice, "Message in a Bottle :)"))

	// Alice Send Message 2
	aliceSentMessages = append(aliceSentMessages, sendMessage(t, alice, "Another Message in a Bottle :)"))

	fmt.Println(alice.toString())

	// Bob Receive Message 2
	_ = receiveMessage(t, bob, aliceSentMessages, 2)

	//Bob Send Message 1 TODO Error comes from here (Bob can't send Messages yet)
	bobSentMessages = append(bobSentMessages, sendMessage(t, bob, "Message in a Bottle :)"))
	bobSentMessages = append(bobSentMessages, sendMessage(t, bob, "Message in a Bottle :)"))

	// Alice Receive Message 1
	_ = receiveMessage(t, alice, bobSentMessages, 2)
	_ = receiveMessage(t, alice, bobSentMessages, 1)

	// Bob Receive Message 1
	_ = receiveMessage(t, bob, aliceSentMessages, 1)
}

func sendMessage(t *testing.T, s *State, msg string) *message {
	fmt.Println("################## sendMessage ##################")

	plaintext := []byte(msg)
	ad := []byte("associatedData")

	header, ciphertext, err := s.RatchetEncrypt(plaintext, ad)
	if err != nil {
		t.Fatal("Could not encrypt message", err.Error())
	}

	fmt.Printf("################## ----------- ##################\n\n\n")
	return &message{
		plaintext:  plaintext,
		ciphertext: ciphertext,
		header:     header,
	}
}

func receiveMessage(t *testing.T, s *State, messages []*message, n int) []byte {
	message := messages[n-1]
	messages[n-1] = nil
	fmt.Printf("################## receiveMessage %d ##################\n", n)

	ad := []byte("associatedData")
	decryptedPlaintext, err := s.RatchetDecrypt(message.header, message.ciphertext, ad)
	if err != nil {
		t.Fatal("Could not decrypt message", err.Error())
	}

	if !bytes.Equal(message.plaintext, decryptedPlaintext) {
		t.Fatal("Did not receive the correct plaintext")
	} else {
		t.Log("Successfully decrypted message")
	}

	fmt.Printf("################## -------------- ##################\n\n\n")
	return decryptedPlaintext
}
