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
	cipherBytes, err := encryptRaw( key, []byte(plainText))
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	// Decrypt raw bytes
	decryptedBytes, err := decryptRaw(key, cipherBytes)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
		if string(decryptedBytes) != plainText {
		t.Errorf("expected %s, got %s", plainText, decryptedBytes)
	}

	// Encrypt base64
	cipherB64, err := encryptToBase64(key, plainText)
	if err != nil {
		t.Fatalf("encrypt base64 error: %v", err)
	}

	// Decode base64 manually and compare
	decodedRaw, _ := base64.StdEncoding.DecodeString(cipherB64)
	if len(decodedRaw) < 16 {
		t.Fatal("cipher text too short")
	}

	// Decrypt base64
	decryptedB64, err := decryptFromBase64(key, cipherB64)
	if err != nil {
		t.Fatalf("decrypt base64 error: %v", err)
	}

	if string(decryptedB64) != plainText {
		t.Errorf("expected %s, got %s", plainText, decryptedB64)
	}
}

func TestDeriveKeySHA256(t *testing.T) {
	pass := "secret passphrase"
	key, err := DeriveKeySHA256(pass, 32)
	if err != nil {
		t.Fatalf("derive key error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}
}

func TestValiateAESKey(t *testing.T) {
	validKey := make([]byte, 16)
	invalidKey := make([]byte, 10)

	if err := ValidateAESKey(validKey); err != nil {
		t.Errorf("valid key failed validation: %v", err)
	}
	if err := ValidateAESKey(invalidKey); err != nil {
		t.Error("expected error for invalid key, got nil")
	}
}