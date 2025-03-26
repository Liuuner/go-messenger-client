package types

import "time"

type SessionModel struct {
	Id        string // chatId
	State     []byte
	Encrypted bool
}

type MessageModel struct {
	Id        string // uuid
	ChatId    string
	Type      string
	Content   []byte
	Encrypted bool
	Timestamp time.Time
}

type ChatModel struct {
	Id                   string
	Username             string
	Encrypted            bool
	TimestampLastMessage time.Time
}
