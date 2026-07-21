package cipher

import (
	"crypto/cipher"
	"fmt"
)

var sbox = [256]byte{
	214, 144, 233, 254, 204, 225, 61, 183, 22, 182, 20, 194, 40, 251, 44, 5,
	43, 103, 154, 118, 42, 190, 4, 195, 170, 68, 19, 38, 73, 134, 6, 153,
	156, 66, 80, 244, 145, 239, 152, 122, 51, 84, 11, 67, 237, 207, 172, 98,
	228, 179, 28, 169, 201, 8, 232, 149, 128, 223, 148, 250, 117, 143, 63, 166,
	71, 7, 167, 252, 243, 115, 23, 186, 131, 89, 60, 25, 230, 133, 79, 168,
	104, 107, 129, 178, 113, 100, 218, 139, 248, 235, 15, 75, 112, 86, 157, 53,
	30, 36, 14, 94, 99, 88, 209, 162, 37, 34, 124, 59, 1, 33, 120, 135,
	212, 0, 70, 87, 159, 211, 39, 82, 76, 54, 2, 231, 160, 196, 200, 158,
	234, 191, 138, 210, 64, 199, 56, 181, 163, 247, 242, 206, 249, 97, 21, 161,
	224, 174, 93, 164, 155, 52, 26, 85, 173, 147, 50, 48, 245, 140, 177, 227,
	29, 246, 226, 46, 130, 102, 202, 96, 192, 41, 35, 171, 13, 83, 78, 111,
	213, 219, 55, 69, 222, 253, 142, 47, 3, 255, 106, 114, 109, 108, 91, 81,
	141, 27, 175, 146, 187, 221, 188, 127, 17, 217, 92, 65, 31, 16, 90, 216,
	10, 193, 49, 136, 165, 205, 123, 189, 45, 116, 208, 18, 184, 229, 180, 176,
	137, 105, 151, 74, 12, 150, 119, 126, 101, 185, 241, 9, 197, 110, 198, 132,
	24, 240, 125, 236, 58, 220, 77, 32, 121, 238, 95, 62, 215, 203, 57, 72,
}

var ck = [32]uint32{
	0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
	0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
	0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
	0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
	0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
	0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
	0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
	0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
}

var fk = [4]uint32{0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC}

type sm4Block struct {
	encRk [32]uint32
	decRk [32]uint32
}

func newSM4Block(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}
	s := &sm4Block{}
	s.encRk = expandKeySM4(true, key)
	s.decRk = expandKeySM4(false, key)
	return s, nil
}

func (s *sm4Block) BlockSize() int { return 16 }

func (s *sm4Block) Encrypt(dst, src []byte) {
	x := [4]uint32{
		bytesToUint32BE(src[0:4]),
		bytesToUint32BE(src[4:8]),
		bytesToUint32BE(src[8:12]),
		bytesToUint32BE(src[12:16]),
	}
	for i := 0; i < 32; i += 4 {
		x[0] = f0(x, s.encRk[i])
		x[1] = f1(x, s.encRk[i+1])
		x[2] = f2(x, s.encRk[i+2])
		x[3] = f3(x, s.encRk[i+3])
	}
	uint32ToBytesBE(x[3], dst[0:4])
	uint32ToBytesBE(x[2], dst[4:8])
	uint32ToBytesBE(x[1], dst[8:12])
	uint32ToBytesBE(x[0], dst[12:16])
}

func (s *sm4Block) Decrypt(dst, src []byte) {
	x := [4]uint32{
		bytesToUint32BE(src[0:4]),
		bytesToUint32BE(src[4:8]),
		bytesToUint32BE(src[8:12]),
		bytesToUint32BE(src[12:16]),
	}
	for i := 0; i < 32; i += 4 {
		x[0] = f0(x, s.decRk[i])
		x[1] = f1(x, s.decRk[i+1])
		x[2] = f2(x, s.decRk[i+2])
		x[3] = f3(x, s.decRk[i+3])
	}
	uint32ToBytesBE(x[3], dst[0:4])
	uint32ToBytesBE(x[2], dst[4:8])
	uint32ToBytesBE(x[1], dst[8:12])
	uint32ToBytesBE(x[0], dst[12:16])
}

func bytesToUint32BE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToBytesBE(v uint32, b []byte) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func rotl(x uint32, bits int) uint32 {
	return x<<bits | x>>(32-bits)
}

func tau(A uint32) uint32 {
	return uint32(sbox[A>>24])<<24 | uint32(sbox[(A>>16)&0xFF])<<16 |
		uint32(sbox[(A>>8)&0xFF])<<8 | uint32(sbox[A&0xFF])
}

func lAp(B uint32) uint32 {
	return B ^ rotl(B, 13) ^ rotl(B, 23)
}

func tAp(Z uint32) uint32 {
	return lAp(tau(Z))
}

func expandKeySM4(forEnc bool, key []byte) [32]uint32 {
	mk := [4]uint32{
		bytesToUint32BE(key[0:4]),
		bytesToUint32BE(key[4:8]),
		bytesToUint32BE(key[8:12]),
		bytesToUint32BE(key[12:16]),
	}
	k := [4]uint32{mk[0] ^ fk[0], mk[1] ^ fk[1], mk[2] ^ fk[2], mk[3] ^ fk[3]}

	var rk [32]uint32
	if forEnc {
		rk[0] = k[0] ^ tAp(k[1]^k[2]^k[3]^ck[0])
		rk[1] = k[1] ^ tAp(k[2]^k[3]^rk[0]^ck[1])
		rk[2] = k[2] ^ tAp(k[3]^rk[0]^rk[1]^ck[2])
		rk[3] = k[3] ^ tAp(rk[0]^rk[1]^rk[2]^ck[3])
		for i := 4; i < 32; i++ {
			rk[i] = rk[i-4] ^ tAp(rk[i-3]^rk[i-2]^rk[i-1]^ck[i])
		}
	} else {
		rk[31] = k[0] ^ tAp(k[1]^k[2]^k[3]^ck[0])
		rk[30] = k[1] ^ tAp(k[2]^k[3]^rk[31]^ck[1])
		rk[29] = k[2] ^ tAp(k[3]^rk[31]^rk[30]^ck[2])
		rk[28] = k[3] ^ tAp(rk[31]^rk[30]^rk[29]^ck[3])
		for i := 27; i >= 0; i-- {
			rk[i] = rk[i+4] ^ tAp(rk[i+3]^rk[i+2]^rk[i+1]^ck[31-i])
		}
	}
	return rk
}

func l(B uint32) uint32 {
	return B ^ rotl(B, 2) ^ rotl(B, 10) ^ rotl(B, 18) ^ rotl(B, 24)
}

func t(Z uint32) uint32 {
	return l(tau(Z))
}

func f0(x [4]uint32, rk uint32) uint32 {
	return x[0] ^ t(x[1]^x[2]^x[3]^rk)
}

func f1(x [4]uint32, rk uint32) uint32 {
	return x[1] ^ t(x[2]^x[3]^x[0]^rk)
}

func f2(x [4]uint32, rk uint32) uint32 {
	return x[2] ^ t(x[3]^x[0]^x[1]^rk)
}

func f3(x [4]uint32, rk uint32) uint32 {
	return x[3] ^ t(x[0]^x[1]^x[2]^rk)
}
