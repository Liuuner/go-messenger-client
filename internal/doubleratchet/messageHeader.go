package doubleratchet

import (
	"bytes"
	"crypto/ecdh"
	"encoding/gob"
)

const MaxSkip = 50

// MessageHeader holds the Double Ratchet message header.
// has to stay public for parsing
type MessageHeader struct {
	DH *ecdh.PublicKey // Ratchet public key
	PN int             // Previous chain length
	N  int             // Message number
}

func CreateMessageHeader(dhPair *ecdh.PrivateKey, pn, n int) *MessageHeader {
	return &MessageHeader{
		DH: dhPair.PublicKey(),
		PN: pn,
		N:  n,
	}
}

func (h *MessageHeader) Equals(other *MessageHeader) bool {
	if h == nil && other == nil {
		return true
	}
	if h.PN != other.PN {
		return false
	}
	if h.N != other.N {
		return false
	}
	if !h.DH.Equal(other.DH) {
		return false
	}
	return true
}

// has to stay public for parsing
type ConcatenationPayload struct {
	AD     []byte
	Header ConcatenationHeader
}

type ConcatenationHeader struct {
	DH []byte
	PN int
	N  int
}

// ConcatHeader Encodes a message header into a parseable byte sequence, prepends the ad byte sequence, and returns the result.
// If ad is not guaranteed to be a parseable byte sequence,
// a length value should be prepended to the output to ensure that the output is parseable as a unique pair (ad, header).
func ConcatHeader(ad []byte, header *MessageHeader) ([]byte, error) {
	payload := ConcatenationPayload{
		AD: ad,
		Header: ConcatenationHeader{
			DH: header.DH.Bytes(),
			PN: header.PN,
			N:  header.N,
		},
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(payload)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func ParseHeader(data []byte) (header *MessageHeader, associatedData []byte, err error) {
	buf := bytes.NewBuffer(data)

	dec := gob.NewDecoder(buf)

	var payload ConcatenationPayload
	err = dec.Decode(&payload)
	if err != nil {
		return nil, nil, err
	}

	curve := ecdh.X25519()
	dh, err := curve.NewPublicKey(payload.Header.DH)
	if err != nil {
		return nil, nil, err
	}

	header = &MessageHeader{
		DH: dh,
		PN: payload.Header.PN,
		N:  payload.Header.N,
	}

	return header, payload.AD, nil
}
