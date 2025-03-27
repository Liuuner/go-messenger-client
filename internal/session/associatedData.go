package session

import "crypto/ecdh"

type associatedData struct {
	localIdentityKey  ecdh.PublicKey
	remoteIdentityKey ecdh.PublicKey
}

// encodeForEncryption returns the ad as a byte slice used for encryption (local + remote)
func (ad *associatedData) encodeForEncryption() []byte {
	return append(ad.localIdentityKey.Bytes(), ad.remoteIdentityKey.Bytes()...)
}

// encodeForDecryption returns the ad as a byte slice used for decryption (remote + local)
func (ad *associatedData) encodeForDecryption() []byte {
	return append(ad.remoteIdentityKey.Bytes(), ad.localIdentityKey.Bytes()...)
}
