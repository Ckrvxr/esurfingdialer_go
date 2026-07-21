package cipher

import (
	"crypto/cipher"
	"crypto/des"
)

type DESedeCBC struct {
	key1 []byte
	key2 []byte
	iv   []byte
}

func NewDESedeCBC(key1, key2, iv []byte) *DESedeCBC {
	return &DESedeCBC{key1: key1, key2: key2, iv: iv}
}

func (d *DESedeCBC) Encrypt(text string) string {
	plaintext := []byte(text)
	padded := Pkcs7Padding(plaintext)

	block, err := des.NewTripleDESCipher(d.key1)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, d.iv)
	out := make([]byte, len(padded))
	mode.CryptBlocks(out, padded)
	return toHex(out)
}

func (d *DESedeCBC) Decrypt(hex string) string {
	data := fromHex(hex)
	block, err := des.NewTripleDESCipher(d.key1)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, d.iv)
	out := make([]byte, len(data))
	mode.CryptBlocks(out, data)
	unpadded, err := Pkcs7UnPadding(out)
	if err != nil {
		panic(err)
	}
	return string(unpadded)
}
