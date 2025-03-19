package types

type Message struct {
	Header     *MessageHeader
	Ciphertext []byte
	Plaintext  []byte
}
