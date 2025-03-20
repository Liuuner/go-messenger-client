CREATE TABLE IF NOT EXISTS chat (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS message (
    id TEXT PRIMARY KEY,
    chat_id TEXT NOT NULL,
    type TEXT NOT NULL,
    content BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,
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

    dh_s BLOB NOT NULL,
    dh_r BLOB NOT NULL,
    rk BLOB NOT NULL,
    cks BLOB NOT NULL,
    ckr BLOB NOT NULL,
    ns INTEGER NOT NULL,
    nr INTEGER NOT NULL,
    pn INTEGER NOT NULL,
    mk_skipped BLOB NOT NULL,

    FOREIGN KEY (chat_id) REFERENCES chat(id)
)