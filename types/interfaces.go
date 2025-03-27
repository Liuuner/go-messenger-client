package types

type Storage interface {
	SaveMessage(sessionId string, message MessageModel) error
	SaveMessages(sessionId string, message []MessageModel) error
	LoadMessages(sessionId string) ([]MessageModel, error)
	SaveSession(sessionId string, session SessionModel) error
	LoadSession(sessionId string) (SessionModel, error)
}

type Transport interface {
	// TODO authentication
	SendMessage(message MessageDTO) error
	SendInitialMessage(message InitialMessageDTO) error
	ReceiveMessages() (<-chan MessageDTO, <-chan InitialMessageDTO, error)
}

type UI interface {
	SendMessage(user string, message Message) error
}
