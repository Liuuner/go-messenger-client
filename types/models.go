package types

import "time"

type SessionModel struct {
	Id        string // chatId
	State     []byte
	Encrypted bool
}

type MessageModel struct { // TODO ????
	Id        string // uuid
	ChatId    string
	Type      string
	Content   []byte
	Encrypted bool
	Timestamp time.Time
}

type ChatModel struct {
	Id                   string // Public IdentityKey of the chat partner as string
	Username             string
	Encrypted            bool
	TimestampLastMessage time.Time
}
