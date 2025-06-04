package transport

import (
	"crypto/ecdh"
	"github.com/Liuuner/signal/internal/doubleratchet"
	"github.com/Liuuner/signal/types"
	"log"
	"time"
)

// Mock is a mock implementation of Transport for testing
type Mock struct {
	interval time.Duration
	stopChan chan struct{}
}

// NewMock creates a new Mock with a given message interval
func NewMock(interval time.Duration) *Mock {
	return &Mock{
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

func (m *Mock) SendMessage(message types.MessageDTO) error {
	log.Println("[TransportMock] Sent message")
	return nil
}

func (m *Mock) SendInitialMessage(message types.MessageDTO) error {
	log.Println("[TransportMock] Sent initial message")
	return nil
}

func (m *Mock) ReceiveMessages() (<-chan types.MessageDTO, error) {
	out := make(chan types.MessageDTO)

	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		defer close(out)

		for {
			select {
			case <-ticker.C:
				msg := types.MessageDTO{
					From:         ecdh.PublicKey{},
					To:           ecdh.PublicKey{},
					Header:       doubleratchet.RatchetHeader{},
					Body:         nil,
					EphemeralKey: nil,
					PreKeyId:     "",
				}
				//log.Printf("[TransportMock] Received message")
				out <- msg
			case <-m.stopChan:
				//log.Println("[TransportMock] Stopping receive loop")
				return
			}
		}
	}()

	return out, nil
}
