package session

import (
	"bytes"
	"crypto/ecdh"
	"encoding/gob"
	"signal/internal/doubleratchet"
	"signal/types"
)

// Session State variables required for a session (maybe user, ...)
type Session struct {
	associatedData *associatedData
	/*
		Alice then calculates an "associated data" byte sequence AD that contains identity information for both parties:

		    AD = Encode(IKA) || Encode(IKB)

		Alice may optionally append additional information to AD, such as Alice and Bob's usernames, certificates, or other identifying information.
	*/
	dr *doubleratchet.State
}

func CreateSessionAndInitialMessage(username string, preKeyBundle types.PreKeyBundle, message []byte) (*Session, *types.InitialMessageDTO, error) {

}

func CreateSessionFromInitialMessage(username string, initialMessage types.InitialMessageDTO, oneTimePreKey *ecdh.PublicKey) (*Session, error) {

}

func (s *Session) EncryptMessage(message []byte) (types.MessageDTO, error) {
	ad := s.associatedData.encodeForEncryption()
}

func (s *Session) DecryptMessage(message types.MessageDTO) ([]byte, error) {
	ad := s.associatedData.encodeForDecryption()
}

func (s *Session) Serialize() []byte {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(s)
	if err != nil {
		return nil
	}
}
