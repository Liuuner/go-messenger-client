package types

import (
	"bytes"
	"crypto/ecdh"
	"encoding/gob"
	"github.com/Liuuner/signal/internal/doubleratchet"
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

type messageBody struct {
	Body        []byte
	ContentType string
	Timestamp   time.Time
}

func (m Message) BodySerialize() ([]byte, error) {
	mb := messageBody{
		Body:        m.Body,
		ContentType: m.ContentType,
		Timestamp:   m.Timestamp,
	}

	// serialize message body with gob
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(mb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func MessageDTOBodyDeserialize(body []byte) (*Message, error) {
	mb := &messageBody{}
	buf := bytes.NewBuffer(body)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(mb)
	if err != nil {
		return nil, err
	}
	return &Message{
		Body:        mb.Body,
		ContentType: mb.ContentType,
		Timestamp:   mb.Timestamp,
	}, nil
}

type MessageDTO struct {
	From   ecdh.PublicKey // sending IdentityKey
	To     ecdh.PublicKey // receiving IdentityKey
	Header doubleratchet.RatchetHeader
	Body   []byte // encrypted message + content type + timestamp

	// for initial message
	EphemeralKey []byte
	PreKeyId     string
}
