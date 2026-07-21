package cipher

const (
	modXTEA_numRounds = 32
	modXTEA_delta     = -1640531527
)

func modXTEA_encryptBlock(v0In, v1In int32, key []int32) (int32, int32) {
	v0 := v0In
	v1 := v1In
	sum := int32(0)
	for i := 0; i < modXTEA_numRounds; i++ {
		sum += modXTEA_delta
		v0 += ((v1 << 4) ^ (v1 >> 5)) + v1 ^ sum + key[sum&3]
		v1 += ((v0 << 4) ^ (v0 >> 5)) + v0 ^ sum + key[(sum>>11)&3]
	}
	return v0, v1
}

func modXTEA_decryptBlock(v0In, v1In int32, key []int32) (int32, int32) {
	v0 := v0In
	v1 := v1In
	delta := int32(modXTEA_delta)
	sum := delta * modXTEA_numRounds
	for i := 0; i < modXTEA_numRounds; i++ {
		v1 -= ((v0 << 4) ^ (v0 >> 5)) + v0 ^ sum + key[(sum>>11)&3]
		v0 -= ((v1 << 4) ^ (v1 >> 5)) + v1 ^ sum + key[sum&3]
		sum -= modXTEA_delta
	}
	return v0, v1
}

func getInt(data []byte, offset int) int32 {
	return int32(data[offset])<<24 | int32(data[offset+1])<<16 |
		int32(data[offset+2])<<8 | int32(data[offset+3])
}

func setInt(data []byte, offset int, value int32) {
	data[offset] = byte(value >> 24)
	data[offset+1] = byte(value >> 16)
	data[offset+2] = byte(value >> 8)
	data[offset+3] = byte(value)
}

func padToMultipleOf8(data []byte) []byte {
	padding := (8 - len(data)%8) % 8
	if padding == 0 {
		return data
	}
	return append(data, make([]byte, padding)...)
}
