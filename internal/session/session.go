package session

import (
	"bytes"
	"crypto/ecdh"
	"encoding/gob"
	"github.com/Liuuner/signal/internal/doubleratchet"
	"github.com/Liuuner/signal/internal/x3dh"
	"github.com/Liuuner/signal/types"
	"time"
)

// Session State variables required for a session (maybe user, ...)
type Session struct {
	associatedData *associatedData
	localUsername  []byte
	remoteUsername []byte
	/*
		Alice then calculates an "associated data" byte sequence AD that contains identity information for both parties:

		    AD = Encode(IKA) || Encode(IKB)

		Alice may optionally append additional information to AD, such as Alice and Bob's usernames, certificates, or other identifying information.
	*/
	dr *doubleratchet.State
}

func CreateSessionAndInitialMessage(from, to string, identityKey ecdh.PrivateKey, preKeyBundle types.PreKeyBundle, message types.Message) (*Session, *types.MessageDTO, error) {
	ad := &associatedData{
		localIdentityKey:  *identityKey.PublicKey(),
		remoteIdentityKey: *preKeyBundle.IdentityKey,
	}

	// Do x3dh
	sharedSecret, ephemeralKey, err := x3dh.GenerateSharedSecretFromKeyBundle(&identityKey, preKeyBundle)
	if err != nil {
		return nil, nil, err
	}

	// create a new Double ratchet
	dr, err := doubleratchet.New(sharedSecret, preKeyBundle.IdentityKey)
	if err != nil {
		return nil, nil, err
	}

	// create session
	session := &Session{
		associatedData: ad,
		localUsername:  []byte(from),
		remoteUsername: []byte(to),
		dr:             dr,
	}

	messageDTO, err := session.EncryptMessage(message)
	if err != nil {
		return nil, nil, err
	}

	messageDTO.EphemeralKey = ephemeralKey.PublicKey().Bytes()
	messageDTO.PreKeyId = preKeyBundle.OneTimePreKeyId

	return session, messageDTO, nil
}

func CreateSessionFromInitialMessage(username string, initialMessage types.MessageDTO, oneTimePreKey *ecdh.PublicKey) (*Session, error) {
	// Todo don't really know what to do here yet
	return nil, nil
}

func (s *Session) EncryptMessage(message types.Message) (*types.MessageDTO, error) {
	ad := s.associatedData.encodeForEncryption()
	message.Timestamp = time.Now()

	mb, err := message.BodySerialize()
	if err != nil {
		return nil, err
	}
	header, ciphertext, err := s.dr.RatchetEncrypt(mb, ad)
	if err != nil {
		return nil, err
	}

	return &types.MessageDTO{
		From:   s.associatedData.localIdentityKey,
		To:     s.associatedData.remoteIdentityKey,
		Header: *header,
		Body:   ciphertext,
	}, nil
}

func (s *Session) DecryptMessage(message types.MessageDTO) (*types.Message, error) {
	ad := s.associatedData.encodeForDecryption()

	plainBody, err := s.dr.RatchetDecrypt(&message.Header, message.Body, ad)
	if err != nil {
		return nil, err
	}

	mb, err := types.MessageDTOBodyDeserialize(plainBody)
	if err != nil {
		return nil, err
	}

	return &types.Message{
		From:        s.remoteUsername,
		To:          s.localUsername,
		Body:        mb.Body,
		ContentType: mb.ContentType,
		Timestamp:   mb.Timestamp,
	}, nil
}

func (s *Session) Serialize() []byte {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(s)
	if err != nil {
		return nil
	}
	return buffer.Bytes()
}
