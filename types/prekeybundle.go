package types

import "crypto/ecdh"

type PreKeyBundle struct {
	IdentityKey     *ecdh.PublicKey // Bob's identity key IK
	SignedPreKey    *ecdh.PublicKey // Bob's signed prekey SPK
	PreKeySignature []byte          // Bob's prekey signature Sig(IKB, Encode(SPK))
	OneTimePreKey   *ecdh.PublicKey // (Optionally) Bob's one-time prekey OPK
}

/*
The server should provide one of Bob's one-time prekeys if one exists, and then delete it.
If all of Bob's one-time prekeys on the server have been deleted, the bundle will not contain a one-time prekey.
*/
