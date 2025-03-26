package types

type Storage interface {
	SaveMessage(sessionId string, message MessageModel) error
	SaveMessages(sessionId string, message []MessageModel) error
	LoadMessages(sessionId string) ([]MessageModel, error)
	SaveSession(sessionId string, session SessionModel) error
	LoadSession(sessionId string) (SessionModel, error)
}

type Transport interface {
	SendMessage(to string, message EncryptedMessage) error
	ReceiveMessages() (<-chan EncryptedMessage, error)
}
