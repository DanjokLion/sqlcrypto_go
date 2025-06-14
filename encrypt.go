package sqlcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// EncryptRaw encrypts the string using AES-256-CBC with a random IV
// Returns IV + ciphertext
func encryptRaw(key []byte, plainText []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes long for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := pkcs7Pad(plainText, aes.BlockSize)
	iv, err := generateIV(aes.BlockSize)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, padded)

	return append(iv, cipherText...), nil
}

// EncryptToBase64 encrypts the string using AES-256-CBC with a random IV
// Returns base64(IV + ciphertext)
func encryptToBase64(key []byte, plainText string) (string, error) {
	data, err := encryptRaw(key, []byte(plainText))
	if err != nil {
		return "", err
	}

	return base64Encode(data), nil
}