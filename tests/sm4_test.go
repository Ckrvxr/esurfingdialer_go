package tests

import (
	"encoding/hex"
	"testing"

	"esurfingdialer/code/cipher"
)

func TestSM4CBCRoundTrip(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	plaintext := "Hello SM4-CBC! This is a test for the campus dialer."

	ciph := cipher.NewSM4CBC(key, iv)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)

	if dec != plaintext {
		t.Fatalf("SM4-CBC round trip failed:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}

func TestSM4ECBRoundTrip(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext := "Hello SM4-ECB! Short msg."

	ciph := cipher.NewSM4ECB(key)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)

	if dec != plaintext {
		t.Fatalf("SM4-ECB round trip failed:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}

func TestSM4CBCEmpty(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	ciph := cipher.NewSM4CBC(key, iv)
	enc := ciph.Encrypt("")
	dec := ciph.Decrypt(enc)
	if dec != "" {
		t.Fatalf("empty string round trip failed: %q", dec)
	}
}

func TestSM4CBCExactBlock(t *testing.T) {
	key := make([]byte, 16)
	key[0] = 0x01
	iv := make([]byte, 16)
	plaintext := "0123456789abcdef"

	ciph := cipher.NewSM4CBC(key, iv)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)
	if dec != plaintext {
		t.Fatalf("exact block round trip failed:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}
