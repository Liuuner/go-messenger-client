package doubleratchet

import (
	"crypto/ecdh"
)

const MaxSkip = 1000

// Info holds the Double Ratchet message header.
// has to stay public for parsing
type Info struct {
	DH *ecdh.PublicKey // Ratchet public key
	PN int             // Previous chain length
	N  int             // Message number
}

func (h *Info) Equals(other *Info) bool {
	if h == nil && other == nil {
		return true
	}
	if h.PN != other.PN {
		return false
	}
	if h.N != other.N {
		return false
	}
	if !h.DH.Equal(other.DH) {
		return false
	}
	return true
}

// has to stay public for parsing
type ConcatenationPayload struct {
	AD     []byte
	Header ConcatenationHeader
}

type ConcatenationHeader struct {
	DH []byte
	PN int
	N  int
}
