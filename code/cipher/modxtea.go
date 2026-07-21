package cipher

type ModXTEA struct {
	key1 []int32
	key2 []int32
	key3 []int32
}

func NewModXTEA(key1, key2, key3 []int32) *ModXTEA {
	return &ModXTEA{key1: key1, key2: key2, key3: key3}
}

func (m *ModXTEA) Encrypt(text string) string {
	blocks := padToMultipleOf8([]byte(text))
	for i := 0; i < len(blocks); i += 8 {
		v0 := getInt(blocks, i)
		v1 := getInt(blocks, i+4)
		v0, v1 = modXTEA_encryptBlock(v0, v1, m.key1)
		v0, v1 = modXTEA_encryptBlock(v0, v1, m.key2)
		v0, v1 = modXTEA_encryptBlock(v0, v1, m.key3)
		setInt(blocks, i, v0)
		setInt(blocks, i+4, v1)
	}
	return toHex(blocks)
}

func (m *ModXTEA) Decrypt(hex string) string {
	blocks := fromHex(hex)
	for i := 0; i < len(blocks); i += 8 {
		v0 := getInt(blocks, i)
		v1 := getInt(blocks, i+4)
		v0, v1 = modXTEA_decryptBlock(v0, v1, m.key3)
		v0, v1 = modXTEA_decryptBlock(v0, v1, m.key2)
		v0, v1 = modXTEA_decryptBlock(v0, v1, m.key1)
		setInt(blocks, i, v0)
		setInt(blocks, i+4, v1)
	}
	blocks = trimZeroTail(blocks)
	return string(blocks)
}
