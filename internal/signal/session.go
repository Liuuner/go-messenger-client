package signal

import (
	"crypto/ecdh"
	"signal/internal/doubleratchet"
	"signal/internal/types"
)

// Session State variables required for a session (maybe user, ...)
type Session struct {
	User string
	*doubleratchet.State
}

func NewSession(user string, sharedSecret []byte, publicKey *ecdh.PublicKey) (*Session, error) {
	drState, err := doubleratchet.New(sharedSecret, publicKey)
	if err != nil {
		return nil, err
	}
	session := &Session{
		user,
		drState,
	}
	return session, nil
}

func (s *Session) CreateEncryptedMessage(plaintext []byte) (*types.Message, error) {
	ad := []byte("associatedData")

	header, ciphertext, err := s.RatchetEncrypt(plaintext, ad)
	if err != nil {
		return nil, err
	}

	return &types.Message{
		Ciphertext: ciphertext,
		Header:     header,
	}, nil
}

func (s *Session) DecryptMessage(message *types.Message) ([]byte, error) {
	// TODO idk if ad should be like this
	ad := []byte("associatedData")
	return s.RatchetDecrypt(message.Header, message.Ciphertext, ad)
}
