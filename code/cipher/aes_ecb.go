package cipher

import (
	"crypto/aes"
)

type AESECB struct {
	key1 []byte
	key2 []byte
}

func NewAESECB(key1, key2 []byte) *AESECB {
	return &AESECB{key1: key1, key2: key2}
}

func aesEncryptECB(plaintext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	padded := plaintext
	if len(padded)%16 != 0 {
		padded = make([]byte, (len(plaintext)/16+1)*16)
		copy(padded, plaintext)
	}
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		block.Encrypt(out[i:i+16], padded[i:i+16])
	}
	return out
}

func aesDecryptECB(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Decrypt(out[i:i+16], data[i:i+16])
	}
	return out
}

func (a *AESECB) Encrypt(text string) string {
	r1 := aesEncryptECB([]byte(text), a.key1)
	r2 := aesEncryptECB(r1, a.key2)
	return toHex(r2)
}

func (a *AESECB) Decrypt(hex string) string {
	data := fromHex(hex)
	r1 := aesDecryptECB(data, a.key2)
	out := aesDecryptECB(r1, a.key1)
	out = trimZeroTail(out)
	return string(out)
}
