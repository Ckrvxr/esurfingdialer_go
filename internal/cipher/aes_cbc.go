package cipher

import (
	"crypto/aes"
	"crypto/cipher"
)

type AESCBC struct {
	key1 []byte
	key2 []byte
	iv   []byte
}

func NewAESCBC(key1, key2, iv []byte) *AESCBC {
	return &AESCBC{key1: key1, key2: key2, iv: iv}
}

func aesEncryptPrependedIV(plaintext, key, iv []byte) []byte {
	padded := plaintext
	if len(padded)%16 != 0 {
		padded = make([]byte, (len(plaintext)/16+1)*16)
		copy(padded, plaintext)
	}
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(padded))
	mode.CryptBlocks(out, padded)
	result := make([]byte, len(iv)+len(out))
	copy(result, iv)
	copy(result[len(iv):], out)
	return result
}

func aesDecryptStripIV(data, key, iv []byte) []byte {
	actual := data[16:]
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(actual))
	mode.CryptBlocks(out, actual)
	return out
}

func (a *AESCBC) Encrypt(text string) string {
	r1 := aesEncryptPrependedIV([]byte(text), a.key1, a.iv)
	r2 := aesEncryptPrependedIV(r1, a.key2, a.iv)
	return toHex(r2)
}

func (a *AESCBC) Decrypt(hex string) string {
	data := fromHex(hex)
	r1 := aesDecryptStripIV(data, a.key2, a.iv)
	out := aesDecryptStripIV(r1, a.key1, a.iv)
	out = trimZeroTail(out)
	return string(out)
}
