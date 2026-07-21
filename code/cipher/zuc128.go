package cipher

var zucS0 = [256]byte{
	62, 114, 91, 71, 202, 224, 0, 51, 4, 209, 84, 152, 9, 185, 109, 203,
	123, 27, 249, 50, 175, 157, 106, 165, 184, 45, 252, 29, 8, 83, 3, 144,
	77, 78, 132, 153, 228, 206, 217, 145, 221, 182, 133, 72, 139, 41, 110, 172,
	205, 193, 248, 30, 115, 67, 105, 198, 181, 189, 253, 57, 99, 32, 212, 56,
	118, 125, 178, 167, 207, 237, 87, 197, 243, 44, 187, 20, 33, 6, 85, 155,
	227, 239, 94, 49, 79, 127, 90, 164, 13, 130, 81, 73, 95, 186, 88, 28,
	74, 22, 213, 23, 168, 146, 36, 31, 140, 255, 216, 174, 46, 1, 211, 173,
	59, 75, 218, 70, 235, 201, 222, 154, 143, 135, 215, 58, 128, 111, 47, 200,
	177, 180, 55, 247, 10, 34, 19, 40, 124, 204, 60, 137, 199, 195, 150, 86,
	7, 191, 126, 240, 11, 43, 151, 82, 53, 65, 121, 97, 166, 76, 16, 254,
	188, 38, 149, 136, 138, 176, 163, 251, 192, 24, 148, 242, 225, 229, 233, 93,
	208, 220, 17, 102, 100, 92, 236, 89, 66, 117, 18, 245, 116, 156, 170, 35,
	14, 134, 171, 190, 42, 2, 231, 103, 230, 68, 162, 108, 194, 147, 159, 241,
	246, 250, 54, 210, 80, 104, 158, 98, 113, 21, 61, 214, 64, 196, 226, 15,
	142, 131, 119, 107, 37, 5, 63, 12, 48, 234, 112, 183, 161, 232, 169, 101,
	141, 39, 26, 219, 129, 179, 160, 244, 69, 122, 25, 223, 238, 120, 52, 96,
}

var zucS1 = [256]byte{
	85, 194, 99, 113, 59, 200, 71, 134, 159, 60, 218, 91, 41, 226, 253, 119,
	140, 197, 148, 12, 166, 26, 19, 0, 227, 168, 22, 114, 64, 249, 248, 66,
	68, 38, 104, 150, 129, 217, 69, 62, 16, 118, 198, 167, 139, 57, 67, 225,
	58, 181, 86, 42, 192, 109, 179, 5, 34, 102, 191, 220, 11, 250, 98, 72,
	221, 32, 17, 6, 54, 201, 193, 207, 246, 39, 82, 187, 105, 245, 212, 135,
	127, 132, 76, 210, 156, 87, 164, 188, 79, 154, 223, 254, 214, 141, 122, 235,
	43, 83, 216, 92, 161, 20, 23, 251, 35, 213, 125, 48, 103, 115, 8, 9,
	238, 183, 112, 63, 97, 178, 25, 142, 78, 229, 75, 147, 143, 93, 219, 169,
	173, 241, 174, 46, 203, 13, 252, 244, 45, 70, 110, 29, 151, 232, 209, 233,
	77, 55, 165, 117, 94, 131, 158, 171, 130, 157, 185, 28, 224, 205, 73, 137,
	1, 182, 189, 88, 36, 162, 95, 56, 120, 153, 21, 144, 80, 184, 149, 228,
	208, 145, 199, 206, 237, 15, 180, 111, 160, 204, 240, 2, 74, 121, 195, 222,
	163, 239, 234, 81, 230, 107, 24, 236, 27, 44, 128, 247, 116, 231, 255, 33,
	90, 106, 84, 30, 65, 49, 146, 53, 196, 51, 7, 10, 186, 126, 14, 52,
	136, 177, 152, 124, 243, 61, 96, 108, 123, 202, 211, 31, 50, 101, 4, 40,
	100, 190, 133, 155, 47, 89, 138, 215, 176, 37, 172, 175, 18, 3, 226, 242,
}

var zucEk_d = [16]uint16{
	17623, 9916, 25195, 4958, 22409, 13794, 28981, 2479,
	19832, 12051, 27588, 6897, 24102, 15437, 30874, 18348,
}

type zuc128State struct {
	lfsr       [16]uint32
	f          [2]uint32
	brc        [4]uint32
	keyStream  [4]byte
	theIndex   int
	theIter    int
}

func (z *zuc128State) addM(a, b uint32) uint32 {
	c := a + b
	return (c & 0x7FFFFFFF) + (c >> 31)
}

func (z *zuc128State) mulByPow2(x uint32, k int) uint32 {
	return (x<<k | x>>(31-k)) & 0x7FFFFFFF
}

func (z *zuc128State) lfsrWithInitialisationMode(u uint32) {
	f := z.lfsr[0]
	v := z.mulByPow2(z.lfsr[0], 8)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[4], 20)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[10], 21)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[13], 17)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[15], 15)
	f = z.addM(f, v)
	f = z.addM(f, u)
	for i := 0; i < 15; i++ {
		z.lfsr[i] = z.lfsr[i+1]
	}
	z.lfsr[15] = f
}

func (z *zuc128State) lfsrWithWorkMode() {
	f := z.lfsr[0]
	v := z.mulByPow2(z.lfsr[0], 8)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[4], 20)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[10], 21)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[13], 17)
	f = z.addM(f, v)
	v = z.mulByPow2(z.lfsr[15], 15)
	f = z.addM(f, v)
	for i := 0; i < 15; i++ {
		z.lfsr[i] = z.lfsr[i+1]
	}
	z.lfsr[15] = f
}

func (z *zuc128State) bitReorganization() {
	z.brc[0] = ((z.lfsr[15] & 0x7FFF8000) << 1) | (z.lfsr[14] & 0xFFFF)
	z.brc[1] = ((z.lfsr[11] & 0xFFFF) << 16) | (z.lfsr[9] >> 15)
	z.brc[2] = ((z.lfsr[7] & 0xFFFF) << 16) | (z.lfsr[5] >> 15)
	z.brc[3] = ((z.lfsr[2] & 0xFFFF) << 16) | (z.lfsr[0] >> 15)
}

func rot(a uint32, k int) uint32 {
	return a<<k | a>>(32-k)
}

func l1(x uint32) uint32 {
	return x ^ rot(x, 2) ^ rot(x, 10) ^ rot(x, 18) ^ rot(x, 24)
}

func l2(x uint32) uint32 {
	return x ^ rot(x, 8) ^ rot(x, 14) ^ rot(x, 22) ^ rot(x, 30)
}

func makeU32(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

func (z *zuc128State) zucF() uint32 {
	w := (z.brc[0] ^ z.f[0]) + z.f[1]
	w1 := z.f[0] + z.brc[1]
	w2 := z.f[1] ^ z.brc[2]

	u := l1((w1 << 16) | (w2 >> 16))
	v := l2((w2 << 16) | (w1 >> 16))

	z.f[0] = makeU32(zucS0[u>>24], zucS1[(u>>16)&0xFF], zucS0[(u>>8)&0xFF], zucS1[u&0xFF])
	z.f[1] = makeU32(zucS0[v>>24], zucS1[(v>>16)&0xFF], zucS0[(v>>8)&0xFF], zucS1[v&0xFF])
	return w
}

func makeU31(a byte, b uint16, c byte) uint32 {
	return uint32(a&0xFF)<<23 | uint32(b)<<8 | uint32(c&0xFF)
}

func (z *zuc128State) setKeyAndIV(k, iv []byte) {
	for i := 0; i < 16; i++ {
		z.lfsr[i] = makeU31(k[i], zucEk_d[i], iv[i])
	}
	z.f[0] = 0
	z.f[1] = 0
	for n := 32; n > 0; n-- {
		z.bitReorganization()
		w := z.zucF()
		z.lfsrWithInitialisationMode(w >> 1)
	}
	z.bitReorganization()
	z.zucF()
	z.lfsrWithWorkMode()
}

func (z *zuc128State) makeKeyStreamWord() uint32 {
	if z.theIter >= 2047 {
		panic("ZUC: too much data processed")
	}
	z.theIter++
	z.bitReorganization()
	result := z.zucF() ^ z.brc[3]
	z.lfsrWithWorkMode()
	return result
}

func (z *zuc128State) makeKeyStream() {
	val := z.makeKeyStreamWord()
	z.keyStream[0] = byte(val >> 24)
	z.keyStream[1] = byte(val >> 16)
	z.keyStream[2] = byte(val >> 8)
	z.keyStream[3] = byte(val)
}

func (z *zuc128State) returnByte(in byte) byte {
	if z.theIndex == 0 {
		z.makeKeyStream()
	}
	out := z.keyStream[z.theIndex] ^ in
	z.theIndex = (z.theIndex + 1) % 4
	return out
}

func (z *zuc128State) processBytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = z.returnByte(in[i])
	}
	return out
}

func newZUC128(key, iv []byte) *zuc128State {
	if len(key) != 16 || len(iv) != 16 {
		panic("ZUC: key and iv must be 16 bytes")
	}
	z := &zuc128State{}
	z.setKeyAndIV(key, iv)
	return z
}
