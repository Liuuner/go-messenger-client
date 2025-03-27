package types

import (
	"crypto/ecdh"
	"signal/internal/doubleratchet"
	"time"
)

// Message holds the message data, it is the data which is sent between ui and session
type Message struct {
	From        []byte
	To          []byte
	Body        []byte // really just the data, no additional metadata and not encrypted
	ContentType string // mime type (e.g. text/plain, image/jpeg, audio/ogg, ...) the ui has to decide how to display it
	Timestamp   time.Time
}

/*func (m *Message) Serialize() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(m)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func DeserializeMessage(data []byte) (*Message, error) {
	var message Message
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(&message)
	if err != nil {
		return nil, err
	}
	return &message, nil
}*/

type SerializedMessage []byte
type EncryptedMessage []byte

type MessageDTO struct {
	From   ecdh.PublicKey // sending IdentityKey
	Header doubleratchet.RatchetHeader
	Body   EncryptedMessage

	// for initial message
	IsInitialMessage bool
	EphemeralKey     []byte
	PreKeyId         string
}
