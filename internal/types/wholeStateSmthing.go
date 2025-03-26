package types

import (
	"crypto/ecdh"
	"os"
	"path"
	"signal/internal/x3dh"
)

type WholeStateSmthing struct {
	IdentityKey *ecdh.PrivateKey
	Sessions    map[string]*Session
	DataDirPath string
	User        *x3dh.User
}

func (w *WholeStateSmthing) New(username, dataDirPath string, options ...option) *Session {

}

// options
type option func(*WholeStateSmthing) error

func WithDataDirPath(dataDirPath string) option {
	return func(w *WholeStateSmthing) error {
		if _, err := os.Stat(dataDirPath); os.IsNotExist(err) {
			return err
		}
		w.DataDirPath = dataDirPath
		return nil
	}
}

func WithDataStorage(b bool) option {
	return func(w *WholeStateSmthing) error {
		w.DataStorage = b
		return nil
	}
}
