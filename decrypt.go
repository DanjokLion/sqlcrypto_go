package sqlcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func DecryptRaw(key []byte, encrypted []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes long for AES-256")
	}

	if len(encrypted) < aes.BlockSize {
		return nil, errors.New("insufficient data: missing IV")
	}

	iv := encrypted[:aes.BlockSize]
	cipherText := encrypted[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherText) % aes.BlockSize != 0 {
		return nil, errors.New("incorrect ciphertext length")
	}

	plainText := make([]byte, len(cipherText))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainText, cipherText)

	return pkcs7Unpad(plainText, aes.BlockSize)
}

func DecryptFromBase64(key []byte, base64data string) (string, error) {
	encrypted, err := Base64Decode(base64data)
	if err != nil {
		return "", err
	} 

	decrypted, err := DecryptRaw(key, encrypted)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}