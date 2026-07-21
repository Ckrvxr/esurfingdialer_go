package cipher

import (
	"crypto/cipher"
)

type SM4CBC struct {
	key []byte
	iv  []byte
}

func NewSM4CBC(key, iv []byte) *SM4CBC {
	return &SM4CBC{key: key, iv: iv}
}

func (s *SM4CBC) Encrypt(text string) string {
	plaintext := []byte(text)
	padded := Pkcs7Padding(plaintext)

	block, err := newSM4Block(s.key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, s.iv)
	out := make([]byte, len(padded))
	mode.CryptBlocks(out, padded)
	return toHex(out)
}

func (s *SM4CBC) Decrypt(hex string) string {
	data := fromHex(hex)
	block, err := newSM4Block(s.key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, s.iv)
	out := make([]byte, len(data))
	mode.CryptBlocks(out, data)
	unpadded, err := Pkcs7UnPadding(out)
	if err != nil {
		panic(err)
	}
	return string(unpadded)
}
