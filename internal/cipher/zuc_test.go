package cipher

import (
	"testing"
)

func TestZUCRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(0xFF - i)
	}
	plaintext := "Hello ZUC! This is a test for stream cipher encryption."

	ciph := NewZUC(key, iv)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)

	if dec != plaintext {
		t.Fatalf("ZUC round trip failed:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}

func TestZUCEmpty(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	ciph := NewZUC(key, iv)
	enc := ciph.Encrypt("")
	dec := ciph.Decrypt(enc)
	if dec != "" {
		t.Fatalf("empty string round trip failed: %q", dec)
	}
}

func TestZUCSingleByte(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	iv := []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}

	ciph := NewZUC(key, iv)
	enc := ciph.Encrypt("A")
	dec := ciph.Decrypt(enc)
	if dec != "A" {
		t.Fatalf("single byte round trip failed: %q", dec)
	}
}

func TestZUCStreamDeterministic(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	ciph1 := NewZUC(key, iv)
	ciph2 := NewZUC(key, iv)

	r1 := ciph1.Encrypt("Hello ZUC!")
	r2 := ciph2.Encrypt("Hello ZUC!")
	if r1 != r2 {
		t.Fatalf("deterministic test failed:\n1: %s\n2: %s", r1, r2)
	}
}

func TestZUCEncryptDecrypt(t *testing.T) {
	key := []byte{0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29}
	iv := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}

	plaintext := "ZUC encryption test vector verification"
	ciph := NewZUC(key, iv)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)
	if dec != plaintext {
		t.Fatalf("ZUC encrypt/decrypt mismatch:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}
