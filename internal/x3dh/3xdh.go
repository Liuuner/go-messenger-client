package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"github.com/Liuuner/signal/internal/doubleratchet"
	"github.com/Liuuner/signal/types"
	"golang.org/x/crypto/hkdf"
	"io"
	"strings"
)

const KDFLen = 32

var (
	KDFSalt = strings.Repeat("\x00", KDFLen)
	KDFF    = strings.Repeat("\xff", KDFLen)
)

func x3dhKDF(keyMaterial []byte) ([]byte, error) {
	km := append([]byte(KDFF), keyMaterial...)
	salt := []byte(KDFSalt)
	hash := sha256.New
	kdf := hkdf.New(hash, km, salt, nil)

	sk := make([]byte, KDFLen)
	if _, err := io.ReadFull(kdf, sk); err != nil {
		return nil, err
	}
	return sk, nil
}

func GenerateSharedSecretFromKeyBundle(identityKey *ecdh.PrivateKey, keyBundle types.PreKeyBundle) (sharedSecret []byte, ephemeralKey *ecdh.PrivateKey, err error) {
	// TODO Alice verifies the prekey signature and aborts the protocol if verification fails. Alice then generates an ephemeral key pair with public key EKA.
	if !ed25519.Verify(identityKey.PublicKey().Bytes(), keyBundle.SignedPreKey.Bytes(), keyBundle.PreKeySignature) {
		return nil, nil, errors.Join(errors.New("unable to verify prekey bundle signature"), err)
	}
	ephemeralKey, err = doubleratchet.GenerateDH()

	dh1, err := doubleratchet.DH(identityKey, keyBundle.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := doubleratchet.DH(ephemeralKey, keyBundle.IdentityKey)
	if err != nil {
		return nil, nil, err
	}
	dh3, err := doubleratchet.DH(ephemeralKey, keyBundle.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}

	var keyMaterial []byte
	//If the bundle does not contain a one-time prekey
	if keyBundle.OneTimePreKey == nil {
		keyMaterial = append(append(dh1, dh2...), dh3...)
	} else {
		// If the bundle does contain a one-time prekey, the calculation is modified to include an additional DH
		dh4, err := doubleratchet.DH(ephemeralKey, keyBundle.OneTimePreKey)
		if err != nil {
			return nil, nil, err
		}
		keyMaterial = append(append(append(dh1, dh2...), dh3...), dh4...)
	}

	sharedSecret, err = x3dhKDF(keyMaterial)
	return sharedSecret, ephemeralKey, err
}
