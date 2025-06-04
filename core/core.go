package core

import (
	"crypto/ecdh"
	"github.com/Liuuner/signal/internal/session"
	"github.com/Liuuner/signal/transport"
	"github.com/Liuuner/signal/types"
	"time"
)

type Core struct {
	identityKey    *ecdh.PrivateKey
	masterPassword string
	username       string
	encryptData    bool
	transport      types.Transport
	storage        types.Storage
	onMessageFunc  func(message types.Message)
	sessions       map[string]*session.Session // identityKey -> session
	preKeys        map[string]*ecdh.PrivateKey
}

func NewDefault() *Core {
	return &Core{}
}

func NewMock(interval time.Duration) *Core {
	return &Core{
		transport: transport.NewMock(interval),
	}
}

func (c *Core) Open(identityKey *ecdh.PrivateKey, masterPassword string) {
	c.identityKey = identityKey
	c.encryptData = masterPassword != ""
	c.masterPassword = masterPassword

}

/*func (c *Core) dispatchMessage() {
	// ui channel dispatch

	// maybe also store message in storage
}*/

func (c *Core) OnMessage(onMessageFunc func(message types.Message)) {
	c.onMessageFunc = onMessageFunc
}

func (c *Core) SendMessage(message types.Message) error {
	return c.transport.SendMessage(types.MessageDTO{})
}

func (c *Core) Start() {
	// start transport receive loop
	receiveChan, err := c.transport.ReceiveMessages()
	if err != nil {
		panic(err)
	}
	go func() {
		for range receiveChan {
			if c.onMessageFunc != nil {
				c.onMessageFunc(types.Message{
					Timestamp: time.Now(),
				})
			}
		}
	}()
}
