package core

import (
	"crypto/ecdh"
	"signal/internal/session"
	"signal/types"
)

type Core struct {
	identityKey    *ecdh.PrivateKey
	masterPassword string
	username       string
	encryptData    bool
	transport      *types.Transport
	storage        *types.Storage
	sessions       map[string]*session.Session
	preKeys        map[string]*ecdh.PrivateKey
}

func NewDefault() *Core {
	return &Core{}
}

func (c *Core) Open(identityKey *ecdh.PrivateKey, masterPassword string) {
	c.identityKey = identityKey
	c.encryptData = masterPassword != ""
	c.masterPassword = masterPassword
}

func (c *Core) dispatchMessage() {
	// ui channel dispatch

	// maybe also store message in storage
}
