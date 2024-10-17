package doubleratchet

import (
	"crypto/ecdh"
	"errors"
)

/*
def RatchetInitBob(state, SK, bob_dh_key_pair):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = SK
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}
*/

// secretKey is the shared secret
func RatchetInitBob(secretKey []byte, bobDHKeyPair *ecdh.PrivateKey) *State {
	return &State{
		DHs:       bobDHKeyPair,
		DHr:       nil,
		RK:        secretKey,
		CKs:       nil,
		CKr:       nil,
		Ns:        0,
		Nr:        0,
		PN:        0,
		MKSkipped: make(map[mkSkippedKey][]byte),
	}
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
}

/*
def RatchetEncrypt(state, plaintext, AD):
	state.CKs, mk = KDF_CK(state.CKs)
	header = HEADER(state.DHs, state.PN, state.Ns)
	state.Ns += 1
	return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
*/

func (s *State) RatchetEncrypt(plaintext, ad []byte) (header *MessageHeader, ciphertext []byte, err error) {
	var mk []byte
	s.CKs, mk = KDFChainKey(s.CKs)
	s.Ns++

	header = CreateHeader(s.DHs, s.PN, s.Ns)
	data, err := Concat(ad, header)
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

func (s *State) RatchetDecrypt(header *MessageHeader, ciphertext, associatedData []byte) (plaintext []byte, err error) {
	backup := *s

	plaintext, err = s.trySkippedMessageKeys(header, ciphertext, associatedData)
	if err == nil {
		*s = backup
		return plaintext, nil
	}

	if header.DH == nil {
		return nil, errors.New("header.DH is nil")
	}
	if s.DHr == nil {
		return nil, errors.New("s.DHr is nil")
	}

	if !header.DH.Equal(s.DHr) {
		err = s.skipMessageKeys(header.PN)
		if err != nil {
			*s = backup
			return nil, err
		}
		err = s.dhRatchet(header)
		if err != nil {
			*s = backup
			return nil, err
		}
	}

	err = s.skipMessageKeys(header.N)
	if err != nil {
		*s = backup
		return nil, err
	}
	var mk []byte
	s.CKr, mk = KDFChainKey(s.CKr)
	s.Nr++

	data, err := Concat(associatedData, header)
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

func (s *State) trySkippedMessageKeys(header *MessageHeader, cypertext, associatedData []byte) ([]byte, error) {
	key := mkSkippedKey{
		DH: string(header.DH.Bytes()),
		N:  header.N,
	}

	if mk, ok := s.MKSkipped[key]; ok {
		delete(s.MKSkipped, key)
		data, err := Concat(associatedData, header)
		if err != nil {
			return nil, err
		}
		if mk != nil {
			return nil, errors.New("mk is nil, error with pointer or smth")
		}
		return Decrypt(mk, cypertext, data)
	}

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
	if s.CKr != nil {
		for s.Nr < until {
			var mk []byte
			s.CKr, mk = KDFChainKey(s.CKr)
			key := mkSkippedKey{
				DH: string(s.DHr.Bytes()),
				N:  s.Nr,
			}
			s.MKSkipped[key] = mk
			s.Nr++
		}
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

func (s *State) dhRatchet(header *MessageHeader) error {
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
