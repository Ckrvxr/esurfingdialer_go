package cipher

type ZUC struct {
	key []byte
	iv  []byte
}

func NewZUC(key, iv []byte) *ZUC {
	return &ZUC{key: key, iv: iv}
}

func (z *ZUC) processZUC(input []byte) []byte {
	padded := input
	if len(input)%4 != 0 {
		padded = make([]byte, (len(input)/4+1)*4)
		copy(padded, input)
	}
	impl := newZUC128(z.key, z.iv)
	return impl.processBytes(padded)
}

func (z *ZUC) Encrypt(text string) string {
	return toHex(z.processZUC([]byte(text)))
}

func (z *ZUC) Decrypt(hex string) string {
	data := fromHex(hex)
	out := z.processZUC(data)
	out = trimZeroTail(out)
	return string(out)
}
