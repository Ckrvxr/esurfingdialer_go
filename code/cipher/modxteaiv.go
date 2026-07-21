package cipher

type ModXTEAIV struct {
	key1 []int32
	key2 []int32
	key3 []int32
	iv   []int32
}

func NewModXTEAIV(key1, key2, key3, iv []int32) *ModXTEAIV {
	return &ModXTEAIV{key1: key1, key2: key2, key3: key3, iv: iv}
}

func (m *ModXTEAIV) xorBlock(v0In, v1In int32, prev []int32) (int32, int32) {
	return prev[0] ^ v0In, prev[1] ^ v1In
}

func (m *ModXTEAIV) Encrypt(text string) string {
	blocks := padToMultipleOf8([]byte(text))
	previous := m.iv
	for i := 0; i < len(blocks); i += 8 {
		v0 := getInt(blocks, i)
		v1 := getInt(blocks, i+4)
		x0, x1 := m.xorBlock(v0, v1, previous)
		x0, x1 = modXTEA_encryptBlock(x0, x1, m.key3)
		x0, x1 = modXTEA_encryptBlock(x0, x1, m.key2)
		x0, x1 = modXTEA_encryptBlock(x0, x1, m.key1)
		setInt(blocks, i, x0)
		setInt(blocks, i+4, x1)
		previous = []int32{x0, x1}
	}
	return toHex(blocks)
}

func (m *ModXTEAIV) Decrypt(hex string) string {
	blocks := fromHex(hex)
	previous := m.iv
	for i := 0; i < len(blocks); i += 8 {
		v0 := getInt(blocks, i)
		v1 := getInt(blocks, i+4)
		r0, r1 := modXTEA_decryptBlock(v0, v1, m.key1)
		r0, r1 = modXTEA_decryptBlock(r0, r1, m.key2)
		r0, r1 = modXTEA_decryptBlock(r0, r1, m.key3)
		x0, x1 := m.xorBlock(r0, r1, previous)
		setInt(blocks, i, x0)
		setInt(blocks, i+4, x1)
		previous = []int32{v0, v1}
	}
	blocks = trimZeroTail(blocks)
	return string(blocks)
}
