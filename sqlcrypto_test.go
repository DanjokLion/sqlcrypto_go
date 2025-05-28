package sqlcrypto

import (
	"testing"
	"encoding/base64"

)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 byte
	plainText := "Hello, SQL Server"
	t.Logf("Key length: %d", len(key))

	// Encrypt raw bytes
	cipherBytes, err := EncryptRaw([]byte(plainText), key)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	// Decrypt raw bytes
	decryptedBytes, err := DecryptRaw(cipherBytes, key)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
		if string(decryptedBytes) != plainText {
		t.Errorf("expected %s, got %s", plainText, decryptedBytes)
	}

	// Encrypt base64
	cipherB64, err := EncryptToBase64(key, plainText)
	if err != nil {
		t.Fatalf("encrypt base64 error: %v", err)
	}

	// Decode base64 manually and compare
	decodedRaw, _ := base64.StdEncoding.DecodeString(cipherB64)
	if len(decodedRaw) < 16 {
		t.Fatal("cipher text too short")
	}

	// Decrypt base64
	decryptedB64, err := DecryptFromBase64(key, cipherB64)
	if err != nil {
		t.Fatalf("decrypt base64 error: %v", err)
	}

	if string(decryptedB64) != plainText {
		t.Errorf("expected %s, got %s", plainText, decryptedB64)
	}
}