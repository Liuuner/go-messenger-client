package types

import "signal/internal/doubleratchet"

type EncryptedMessageDTO struct {
	Header     *doubleratchet.RatchetHeader
	Ciphertext []byte
}
