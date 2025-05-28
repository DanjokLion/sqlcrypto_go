package sqlcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const AESBlockSize = 16

// GenerateIV generates a random IV of length AESBlockSize
func GenerateIVAES() ([]byte, error) {
	iv := make([]byte, AESBlockSize)
	_, err := rand.Read(iv) 
	if err != nil {
		return nil, fmt.Errorf("IV generation error: %w", err)
	}

	return iv, nil
}

// Generate IV generates an IV of a specific length AES Block Size
func GenerateIV(size int) ([]byte, error) {
	iv := make([]byte, size)
	_, err := rand.Read(iv) 
	if err != nil {
		return nil, fmt.Errorf("IV generation error: %w", err)
	}

	return iv, nil
}

// Base64Encode encodes binary data into a base64 string
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes base64 string into binary
func Base64Decode(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding error:  %w", err)
	}

	return decoded, nil
}

// pkcs7Pad - adds padding to a block
func pkcs7Pad (data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

// pkcs7Pad - remove padding to a block
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid length of decrypted data")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("incorrect padding")
	}

	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("padding verification error")
		}
	}

	return data[:len(data)-padLen], nil

}