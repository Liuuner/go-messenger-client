package storage

import (
	"database/sql"
	"github.com/Liuuner/signal/types"
	"time"
)

type SQLiteStorage struct {
	db *sql.DB
}

func NewSQLiteStorage(db *sql.DB) *types.Storage {
	return &SQLiteStorage{db: db}
}

func (s *SQLiteStorage) SaveMessage(sessionId string, message types.MessageModel) error {
	_, err := s.db.Exec("INSERT INTO messages (id, chat_id, type, content, encrypted, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
		message.Id, message.ChatId, message.Type, message.Content, message.Encrypted, message.Timestamp)
	return err
}

func (s *SQLiteStorage) SaveMessages(sessionId string, messages []types.MessageModel) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO messages (id, chat_id, type, content, encrypted, timestamp) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, message := range messages {
		_, err = stmt.Exec(message.Id, message.ChatId, message.Type, message.Content, message.Encrypted, message.Timestamp)
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLiteStorage) LoadMessages(sessionId string) ([]types.MessageModel, error) {
	rows, err := s.db.Query("SELECT id, chat_id, type, content, encrypted, timestamp FROM messages WHERE chat_id = ?", sessionId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []types.MessageModel
	for rows.Next() {
		var message types.MessageModel
		var timestamp int64
		err := rows.Scan(&message.Id, &message.ChatId, &message.Type, &message.Content, &message.Encrypted, &timestamp)
		if err != nil {
			return nil, err
		}
		message.Timestamp = time.Unix(0, timestamp)
		messages = append(messages, message)
	}
	return messages, nil
}

func (s *SQLiteStorage) SaveSession(sessionId string, session types.SessionModel) error {
	_, err := s.db.Exec("INSERT INTO sessions (id, state, encrypted) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET state=excluded.state, encrypted=excluded.encrypted",
		session.Id, session.State, session.Encrypted)
	return err
}

func (s *SQLiteStorage) LoadSession(sessionId string) (types.SessionModel, error) {
	var session types.SessionModel
	err := s.db.QueryRow("SELECT id, state, encrypted FROM sessions WHERE id = ?", sessionId).Scan(&session.Id, &session.State, &session.Encrypted)
	return session, err
}

func (s *SQLiteStorage) GetChatById(chatId string) (types.ChatModel, error) {
	var chat types.ChatModel
	err := s.db.QueryRow("SELECT id, username, encrypted, timestamp_last_message FROM chats WHERE id = ?", chatId).Scan(&chat.Id, &chat.Username, &chat.Encrypted, &chat.TimestampLastMessage)
	return chat, err
}

func (s *SQLiteStorage) GetChatByUsername(username string) (types.ChatModel, error) {
	var chat types.ChatModel
	err := s.db.QueryRow("SELECT id, username, encrypted, timestamp_last_message FROM chats WHERE username = ?", username).Scan(&chat.Id, &chat.Username, &chat.Encrypted, &chat.TimestampLastMessage)
	return chat, err
}
