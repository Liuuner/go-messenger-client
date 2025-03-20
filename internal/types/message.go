package types

import "signal/internal/doubleratchet"

type Message struct {
	Header     *doubleratchet.MessageHeader
	Ciphertext []byte
	//Plaintext  []byte
}
