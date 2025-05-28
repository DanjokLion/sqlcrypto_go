package sqlcrypto

import (
	"crypto/sha256"
	"errors"
)

// Min and max key lengths accepted by AES (bytes)
const (
	AES128KeyLen = 16
	AES192KeyLen = 24
	AES256KeyLen = 32
)

// hashes an arbitrary string and returns an AES key of the required length (default 32 bytes)
func DeriveKeySHA256(passphrase string, keyLen int) ([]byte, error) {
	if keyLen != AES128KeyLen && keyLen != AES192KeyLen && keyLen != AES256KeyLen {
		return nil, errors.New("unsupported key length")
	}

	hash := sha256.Sum256([]byte(passphrase))
	return hash[:keyLen], nil
}

func ValidateAESKey(key []byte) error {
	switch len(key) {
	case AES128KeyLen, AES192KeyLen, AES256KeyLen:
		return nil
	default:
		return errors.New("invalid AES key length")
	}
}