package doubleratchet

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"maps"
)

type mkSkippedKey struct {
	DH string
	N  int
}

// State variables
type State struct {
	DHs       *ecdh.PrivateKey        // DH Ratchet key pair (sending)
	DHr       *ecdh.PublicKey         // DH Ratchet public key (received)
	RK        []byte                  // Root key
	CKs       []byte                  // Chain key (sending)
	CKr       []byte                  // Chain key (receiving)
	Ns, Nr    int                     // Message numbers for sending and receiving
	PN        int                     // Number of messages in the previous sending chain
	MKSkipped map[mkSkippedKey][]byte // Skipped message keys
}

func New(sharedSecret []byte, remotePublicKey *ecdh.PublicKey) (*State, error) {
	keyPair, err := GenerateDH()
	if err != nil {
		return nil, err
	}

	s := &State{
		DHs:       keyPair,
		DHr:       remotePublicKey,
		RK:        sharedSecret,
		CKs:       nil,
		CKr:       nil,
		Ns:        0,
		Nr:        0,
		PN:        0,
		MKSkipped: make(map[mkSkippedKey][]byte),
	}

	if remotePublicKey != nil {
		dhOut, err := DH(s.DHs, s.DHr)
		if err != nil {
			return nil, err
		}
		s.RK, s.CKs, err = KDFRootKey(sharedSecret, dhOut)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

/*
def RatchetInitAlice(state, SK, bob_dh_public_key):
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}
*/
/*
// secretKey is the shared secret
func RatchetInitAlice(secretKey []byte, bobDHPublicKey *ecdh.PublicKey) (s *State, err error) {
	s = &State{
		DHr:       bobDHPublicKey,
		CKr:       nil,
		Ns:        0,
		Nr:        0,
		PN:        0,
		MKSkipped: make(map[mkSkippedKey][]byte),
	}

	s.DHs, err = GenerateDH()
	if err != nil {
		return nil, err
	}

	dhOut, err := DH(s.DHs, s.DHr)
	if err != nil {
		return nil, err
	}
	s.RK, s.CKs, err = KDFRootKey(secretKey, dhOut)
	if err != nil {
		return nil, err
	}

	return s, nil
}*/

/*
def RatchetEncrypt(state, plaintext, AD):
	state.CKs, mk = KDF_CK(state.CKs)
	header = HEADER(state.DHs, state.PN, state.Ns)
	state.Ns += 1
	return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
*/

func (s *State) RatchetEncrypt(plaintext, associatedData []byte) (header *RatchetHeader, ciphertext []byte, err error) {
	var mk []byte
	s.CKs, mk = KDFChainKey(s.CKs)
	s.Ns++

	header = CreateMessageHeader(s.DHs, s.PN, s.Ns)
	data, err := ConcatHeader(associatedData, header)
	if err != nil {
		return nil, nil, err
	}

	//fmt.Printf("Encrypt called with mk: %v\n plaintext:%v\n associatedData:%v", mk, plaintext, data)
	ciphertext, err = Encrypt(mk, plaintext, data)
	if err != nil {
		return nil, nil, err
	}

	return header, ciphertext, nil
}

/*
def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    if header.dh != state.DHr:
        SkipMessageKeys(state, header.pn)
        DHRatchet(state, header)
    SkipMessageKeys(state, header.n)
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1
    return DECRYPT(mk, ciphertext, CONCAT(AD, header))
*/

func (s *State) RatchetDecrypt(header *RatchetHeader, ciphertext, associatedData []byte) (plaintext []byte, err error) {
	backup := *s

	plaintext, err = s.trySkippedMessageKeys(header, ciphertext, associatedData)
	if err == nil {
		return plaintext, nil
	} else {
		//fmt.Printf("TrySkippedMessageKeys failed with error: %s\n", err.Error())
	}

	if header.DH == nil {
		return nil, errors.New("header.DH is nil")
	}

	// has to be set for initial message
	if s.DHr == nil {
		// TODO maybe s.DHr should be set to header.DH
		log.Print("WARN! s.DHr is set to incoming header.DH, might be a security issue")
		s.DHr = header.DH
	}

	// make ratchet step if initial message
	if len(s.CKr) == 0 {
		//fmt.Println("s.CKr is nil")
		err = s.dhRatchet(header)
		if err != nil {
			//fmt.Println("Error in dhRatchet when CKr is nil")
			*s = backup
			return nil, err
		}
	}

	//fmt.Printf("RatchetDecrypt header.DH: %s, s.DHr: %s\n", header.DH.Bytes(), s.DHr.Bytes())
	if !header.DH.Equal(s.DHr) {
		//fmt.Println("Header.DH isn't equal to s.DHr")
		err = s.skipMessageKeys(header.PN)
		if err != nil {
			*s = backup
			return nil, err
		}
		//fmt.Printf("Run s.dhRatchet\n")
		err = s.dhRatchet(header)
		if err != nil {
			*s = backup
			return nil, err
		}
	} else {
		//fmt.Println("Header.DH is equal to s.DHr")
		s.Nr++

	}

	//fmt.Println("Message Keys to be Skipped", header.N)
	err = s.skipMessageKeys(header.N)
	if err != nil {
		*s = backup
		return nil, err
	}

	var mk []byte
	s.CKr, mk = KDFChainKey(s.CKr)
	s.Nr++

	data, err := ConcatHeader(associatedData, header)
	if err != nil {
		*s = backup
		return nil, err
	}

	plaintext, err = Decrypt(mk, ciphertext, data)
	if err != nil {
		*s = backup
		return nil, err
	}
	return plaintext, nil
}

/*
def TrySkippedMessageKeys(state, header, ciphertext, AD):
    if (header.dh, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, header.n]
        del state.MKSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
    else:
        return None
*/

func (s *State) trySkippedMessageKeys(header *RatchetHeader, ciphertext, associatedData []byte) ([]byte, error) {
	key := mkSkippedKey{
		DH: string(header.DH.Bytes()),
		N:  header.N,
	}

	//fmt.Printf("TrySkippedMessageKey with key: %+v\n", key)

	if mk, ok := s.MKSkipped[key]; ok {
		//fmt.Printf("Found Skipped Message Key: %+v\n", key)
		//fmt.Printf("Found Message Key: %+v\n", mk)
		delete(s.MKSkipped, key)
		//fmt.Printf("Found Message Key after deleting entry: %+v\n", mk)
		data, err := ConcatHeader(associatedData, header)
		if err != nil {
			return nil, err
		}
		if mk == nil {
			return nil, errors.New("mk is nil, error with pointer or smth")
		}
		tempPlaintext, tempErr := Decrypt(mk, ciphertext, data)
		if tempErr != nil {
			//fmt.Printf("Error Decrypting Message Key: %+v with error: %s\n", key, err.Error())
			return nil, tempErr
		}
		//fmt.Printf("Decrypted Plaintext: %s with Skipped Message Key: %+v\n", tempPlaintext, key)
		return tempPlaintext, nil
	}
	//fmt.Printf("No Skipped Message Key Found with Key: %+v\n", key)
	return nil, errors.New("no skipped message keys")
}

/*
def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Error()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            state.MKSKIPPED[state.DHr, state.Nr] = mk
            state.Nr += 1
*/

func (s *State) skipMessageKeys(until int) error {
	if s.Nr+MaxSkip < until {
		return errors.New("skipping to many messages (MaxSkip)")
	}
	//fmt.Printf("s.CKr: %s; length: %d\n", s.CKr, len(s.CKr))
	if len(s.CKr) != 0 {
		for s.Nr < until {
			var mk []byte
			s.CKr, mk = KDFChainKey(s.CKr)
			key := mkSkippedKey{
				DH: string(s.DHr.Bytes()),
				N:  s.Nr,
			}
			//fmt.Printf("Skipping MessageKey with key: %+v\n", key)
			s.MKSkipped[key] = mk
			s.Nr++
		}
	} else {
		//fmt.Println("s.CKr is nil, cannot skip message keys")
		/*dhOut, err := DH(s.DHs, s.DHr)
		if err != nil {
			return err
		}
		s.RK, s.CKr, err = KDFRootKey(s.RK, dhOut)
		if err != nil {
			return err
		}
		s.Nr++*/
	}
	return nil
}

/*
def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
*/

func (s *State) dhRatchet(header *RatchetHeader) error {
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0
	s.DHr = header.DH

	// state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
	dhOut, err := DH(s.DHs, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKr, err = KDFRootKey(s.RK, dhOut)
	if err != nil {
		return err
	}

	s.DHs, err = GenerateDH()
	if err != nil {
		return err
	}

	// state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
	dhOut, err = DH(s.DHs, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKs, err = KDFRootKey(s.RK, dhOut)
	if err != nil {
		return err
	}
	return nil
}

func (s *State) toString() string {
	return fmt.Sprintf("State{DHs: %s, DHr: %s, RK: %s, CKs: %s, CKr: %s, Ns: %d, Nr: %d, PN: %d, MKSkipped: %v}",
		byteSliceToBase64(s.DHs.PublicKey().Bytes()),
		byteSliceToBase64(s.DHr.Bytes()),
		byteSliceToBase64(s.RK),
		byteSliceToBase64(s.CKs),
		byteSliceToBase64(s.CKr),
		s.Ns,
		s.Nr,
		s.PN,
		maps.Keys(s.MKSkipped),
	)
}

func byteSliceToBase64(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)[:5]
}

func (s *State) GetPublicKey() *ecdh.PublicKey {
	return s.DHs.PublicKey()
}
