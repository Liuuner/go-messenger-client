package x3dh

/**
https://lianglouise.github.io/post/some_practice_on_implementing_signal_protocol_with_python_1/
**/
/*
type User struct {
	name               string
	IdentityKey        *ecdh.PrivateKey       // Long-Term Identity Key (32 bytes), which is an unique identifier for each client
	SignedPreKey       *ecdh.PrivateKey       // Signed PreKey (32 bytes), a key pair will be revoked and re-generated every few days/weeks for sake of security.
	SignedPreKeySigned []byte                 // SPK public key’s signature, signed by IK secret key - SIG(IK_s, SPK_p)
	OKPs               []*ecdh.PrivateKey     // One-time Off Key (32 bytes), a key pair will be revoked once used for handshake. Usually, the client will generate multiple OPK pair and generate new one once server used up or needs more.
	KeyBundles         map[string]interface{} // unsure yet
	DrKeys             map[string]interface{} // unsure yet
}

func NewUser(name string, MAX_OPK_NUM int) (*User, error) {
	user := &User{
		name:       name,
		KeyBundles: make(map[string]interface{}),
		DrKeys:     make(map[string]interface{}),
	}

	var err error
	user.IdentityKey, err = doubleratchet.GenerateDH()
	if err != nil {
		return nil, err
	}

	user.SignedPreKey, err = doubleratchet.GenerateDH()
	if err != nil {
		return nil, err
	}

	user.SignedPreKeySigned = ed25519.Sign(user.IdentityKey.Bytes(), user.SignedPreKey.PublicKey().Bytes())

	for range MAX_OPK_NUM {
		sk, err := doubleratchet.GenerateDH()
		if err != nil {
			return nil, err
		}
		user.OKPs = append(user.OKPs, sk)
	}

	return user, nil
}

func (u *User) Publish() KeyBundleSending {
	return KeyBundleSending{
		IdentityKey:        u.IdentityKey.PublicKey(),
		SignedPreKey:       u.SignedPreKey.PublicKey(),
		SignedPreKeySigned: u.SignedPreKeySigned,
		OneTimePreKeys:     getPublicKeysBytes(u.OKPs),
	}
}

func getPublicKeysBytes(keys []*ecdh.PrivateKey) []*ecdh.PublicKey {
	publicKeys := make([]*ecdh.PublicKey, len(keys))
	for i, key := range keys {
		publicKeys[i] = key.PublicKey()
	}
	return publicKeys
}
*/
