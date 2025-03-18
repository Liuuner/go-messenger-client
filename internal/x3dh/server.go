package x3dh

type Server struct{}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) GetKeyBundle(userName string) KeyBundleSending {
	// Return dummy data for the key bundle
	return KeyBundleSending{
		IdentityKey:        nil,
		SignedPreKey:       nil,
		SignedPreKeySigned: nil,
		OneTimePreKeys:     nil,
	}
}
