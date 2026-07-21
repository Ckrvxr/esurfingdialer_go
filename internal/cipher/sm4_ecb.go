package cipher

type SM4ECB struct {
	key []byte
}

func NewSM4ECB(key []byte) *SM4ECB {
	return &SM4ECB{key: key}
}

func (s *SM4ECB) Encrypt(text string) string {
	plaintext := []byte(text)
	padded := Pkcs7Padding(plaintext)

	block, err := newSM4Block(s.key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		block.Encrypt(out[i:i+16], padded[i:i+16])
	}
	return toHex(out)
}

func (s *SM4ECB) Decrypt(hex string) string {
	data := fromHex(hex)
	block, err := newSM4Block(s.key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Decrypt(out[i:i+16], data[i:i+16])
	}
	unpadded, err := Pkcs7UnPadding(out)
	if err != nil {
		panic(err)
	}
	return string(unpadded)
}
