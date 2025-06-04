package x3dh

/*
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"signal/internal/doubleratchet"
	"strings"
)

const KDFLen = 32

var (
	KDFSalt = strings.Repeat("\x00", KDFLen)
	KDFF    = strings.Repeat("\xff", KDFLen)
)

// TODO Split in two structs one for receiving and one for sending (different keys)
type KeyBundleSending struct {
	IdentityKey        *ecdh.PublicKey
	SignedPreKey       *ecdh.PublicKey
	SignedPreKeySigned []byte
	OneTimePreKeys     []*ecdh.PublicKey
}

type KeyBundleReceiving struct {
	EphemeralKey       *ecdh.PrivateKey
	SecretKey          []byte
	IdentityKey        *ecdh.PublicKey
	SignedPreKey       *ecdh.PublicKey
	SignedPreKeySigned []byte
	OneTimePreKeys     []*ecdh.PublicKey
	OneTimePreKey      *ecdh.PublicKey
}

type AssociatedData struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Message string `json:"message"`
}

type Client struct {
	UserName    string
	IdentityKey *ecdh.PrivateKey
	keyBundles  map[string]KeyBundleReceiving
	drKeys      map[string]struct{}
}

func NewClient() *Client {
	return &Client{
		keyBundles: make(map[string]KeyBundleReceiving),
		drKeys:     make(map[string]struct{}),
	}
}

func (c *Client) GetKeyBundle(server Server, userName string) bool {
	if _, ok := c.keyBundles[userName]; ok {
		if _, ok := c.drKeys[userName]; ok {
			fmt.Println("Already stored " + userName + " locally, no need handshake again")
			return false
		}
	}

	c.keyBundles[userName] = server.GetKeyBundle(userName)
	return true
}

func (c *Client) InitialHandshake(server Server, userName string) error {
	if c.GetKeyBundle(server, userName) {
		// Generate Ephemeral Key Pair
		ek, err := doubleratchet.GenerateDH()
		if err != nil {
			fmt.Println("Error generating ephemeral key:", err)
			return err
		}
		c.keyBundles[userName].EphemeralKey = ek
		return nil
	}
	return nil
}

func x3dhKDF(keyMaterial []byte) ([]byte, error) {
	km := append([]byte(KDFF), keyMaterial...)
	salt := []byte(KDFSalt)
	hash := sha256.New
	kdf := hkdf.New(hash, km, salt, nil)

	sk := make([]byte, KDFLen)
	if _, err := io.ReadFull(kdf, sk); err != nil {
		return nil, err
	}
	return sk, nil
}

func (c *Client) GenerateSendSecretKey(userName string) error {
	keyBundle, ok := c.keyBundles[userName]
	if !ok {
		return fmt.Errorf("key bundle for user %s not found", userName)
	}

	DH1, err := doubleratchet.DH(c.IdentityKey, keyBundle.SignedPreKey)
	if err != nil {
		return err
	}
	DH2, err := doubleratchet.DH(keyBundle.EphemeralKey, keyBundle.IdentityKey)
	if err != nil {
		return err
	}
	DH3, err := doubleratchet.DH(keyBundle.EphemeralKey, keyBundle.SignedPreKey)
	if err != nil {
		return err
	}
	DH4, err := doubleratchet.DH(keyBundle.EphemeralKey, keyBundle.OneTimePreKey)
	if err != nil {
		return err
	}

	if !ed25519.Verify(c.IdentityKey.PublicKey().Bytes(), keyBundle.SignedPreKey.Bytes(), keyBundle.SignedPreKeySigned) {
		return fmt.Errorf("unable to verify signed prekey")
	}

	sk, err := x3dhKDF(append(append(append(DH1, DH2...), DH3...), DH4...))
	if err != nil {
		return err
	}

	keyBundle.SecretKey = sk
	return nil
}

func (c *Client) BuildX3DHHello(userName string, ad string) (*KeyBundleSending, error) {
	// TODO may not be correct implementation, likely to be a failure point
	binaryAd, err := json.Marshal(AssociatedData{
		From:    c.UserName,
		To:      userName,
		Message: ad,
	})
	if err != nil {
		return nil, err
	}

	keyBundle, ok := c.keyBundles[userName]
	if !ok {
		return nil, fmt.Errorf("key bundle for user %s not found", userName)
	}

	// 64 byte signature
	key_comb := append(append(c.IdentityKey.PublicKey().Bytes(), keyBundle.EphemeralKey.PublicKey().Bytes()...), keyBundle.OneTimePreKey.Bytes()...)
	signature := ed25519.Sign(c.IdentityKey.Bytes(), append(key_comb, binaryAd...))

	// 16 byte random aes nonce
	nonce := make([]byte, aes.BlockSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	cipherBlock, err := aes.NewCipher(keyBundle.SecretKey)
	// 32 + 32 + len(ad) byte cipher text
	cipherText, err := cipher.NewGCM(cipherBlock)

	return &KeyBundleSending{
		IdentityKey:        c.IdentityKey.PublicKey(),
		SignedPreKey:       keyBundle.SignedPreKey,
		SignedPreKeySigned: keyBundle.SignedPreKeySigned,
		OneTimePreKeys:     keyBundle.OneTimePreKeys,
	}, nil
}
*/
