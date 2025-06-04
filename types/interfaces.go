package types

type Storage interface {
	SaveMessage(sessionId string, message MessageModel) error
	SaveMessages(sessionId string, message []MessageModel) error
	LoadMessages(sessionId string) ([]MessageModel, error)
	SaveSession(sessionId string, session SessionModel) error
	LoadSession(sessionId string) (SessionModel, error)
	GetChatById(chatId string) (ChatModel, error)
	GetChatByUsername(username string) (ChatModel, error)
}

type Transport interface {
	// TODO authentication
	SendMessage(message MessageDTO) error
	SendInitialMessage(message MessageDTO) error
	ReceiveMessages() (<-chan MessageDTO, error)
}
