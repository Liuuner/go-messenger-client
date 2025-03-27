CREATE TABLE IF NOT EXISTS chat (
    id TEXT PRIMARY KEY, /* public identityKey as string */
    username TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL,
    timestamp_last_message TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS message (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    type TEXT NOT NULL,
    content BLOB NOT NULL,
    encrypted BOOLEAN NOT NULL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (chat_id) REFERENCES chat(id)
);

/*
 type State struct {
	DHs       *ecdh.PrivateKey        // DH Ratchet key pair (sending)
	DHr       *ecdh.PublicKey         // DH Ratchet public key (received)
	RK        []byte                  // Root key
	CKs       []byte                  // Chain key (sending)
	CKr       []byte                  // Chain key (receiving)
	Ns, Nr    int                     // Message numbers for sending and receiving
	PN        int                     // Number of messages in the previous sending chain
	MKSkipped map[mkSkippedKey][]byte // Skipped message keys
}
 */

CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    state BLOB NOT NULL,
    encrypted BOOLEAN NOT NULL,
    FOREIGN KEY (chat_id) REFERENCES chat(id)
)