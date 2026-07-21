package cipher

import (
	"crypto/des"
)

type DESedeECB struct {
	key1 []byte
	key2 []byte
}

func NewDESedeECB(key1, key2 []byte) *DESedeECB {
	return &DESedeECB{key1: key1, key2: key2}
}

func desedeEncryptECB(plaintext, key []byte) []byte {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	padded := plaintext
	if len(padded)%8 != 0 {
		padded = make([]byte, (len(plaintext)/8+1)*8)
		copy(padded, plaintext)
	}
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 8 {
		block.Encrypt(out[i:i+8], padded[i:i+8])
	}
	return out
}

func desedeDecryptECB(data, key []byte) []byte {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block.Decrypt(out[i:i+8], data[i:i+8])
	}
	return out
}

func (d *DESedeECB) Encrypt(text string) string {
	r1 := desedeEncryptECB([]byte(text), d.key1)
	r2 := desedeEncryptECB(r1, d.key2)
	return toHex(r2)
}

func (d *DESedeECB) Decrypt(hex string) string {
	data := fromHex(hex)
	r1 := desedeDecryptECB(data, d.key2)
	out := desedeDecryptECB(r1, d.key1)
	out = trimZeroTail(out)
	return string(out)
}
