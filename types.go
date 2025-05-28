package sqlcrypto

type CipherText struct {
	IV 			[]byte
	CipherRaw 	[]byte 
}

type EncryptOptions struct {
	Key []byte
}

type DecryptOptions struct {
	Key []byte
}