package session

import (
	"signal/internal/doubleratchet"
)

// Session State variables required for a session (maybe user, ...)
type Session struct {
	AssociatedData *doubleratchet.associatedData
	/*
		Alice then calculates an "associated data" byte sequence AD that contains identity information for both parties:

		    AD = Encode(IKA) || Encode(IKB)

		Alice may optionally append additional information to AD, such as Alice and Bob's usernames, certificates, or other identifying information.
	*/
	*doubleratchet.State
}

/*func NewSession(sharedSecret []byte, publicKey *ecdh.PublicKey) (*Session, error) {
	drState, err := doubleratchet.New(sharedSecret, publicKey)
	if err != nil {
		return nil, err
	}
	ad := []byte("associatedData")
	session := &Session{
		ad,
		drState,
	}
	return session, nil
}

func (s *Session) CreateEncryptedMessage(plaintext []byte) (*types.Message, error) {

	header, ciphertext, err := s.RatchetEncrypt(plaintext, s.AssociatedData)
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
*/
