package types

import "crypto/ecdh"

type WholeStateSmthing struct {
	IdentityKey *ecdh.PrivateKey
}
