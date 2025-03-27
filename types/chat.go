package types

import "time"

type Chat struct {
	Id                   string // Public IdentityKey of the chat partner as string
	Name                 string // Username of the chat partner
	TimestampLastMessage time.Time
}
