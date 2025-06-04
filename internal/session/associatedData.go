package session

import "crypto/ecdh"

type associatedData struct {
	localIdentityKey  ecdh.PublicKey
	remoteIdentityKey ecdh.PublicKey
	localUsername     string
	remoteUsername    string
}

// encodeForEncryption returns the ad as a byte slice used for encryption (local + remote)
func (ad *associatedData) encodeForEncryption() []byte {
	return append(append(ad.localIdentityKey.Bytes(), []byte(ad.localUsername)...), append(ad.remoteIdentityKey.Bytes(), []byte(ad.remoteUsername)...)...)
}

// encodeForDecryption returns the ad as a byte slice used for decryption (remote + local)
func (ad *associatedData) encodeForDecryption() []byte {
	return append(append(ad.remoteIdentityKey.Bytes(), []byte(ad.remoteUsername)...), append(ad.localIdentityKey.Bytes(), []byte(ad.localUsername)...)...)
}
