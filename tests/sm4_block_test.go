package tests

import (
	"encoding/hex"
	"testing"

	"esurfingdialer/internal/cipher"
)

func TestSM4StandardVector(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plain, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	expected, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")

	block, err := cipher.NewSM4Block(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	block.Encrypt(out, plain)
	if hex.EncodeToString(out) != hex.EncodeToString(expected) {
		t.Fatalf("encrypt mismatch:\ngot:  %s\nexp:  %s", hex.EncodeToString(out), hex.EncodeToString(expected))
	}

	dec := make([]byte, 16)
	block.Decrypt(dec, out)
	if hex.EncodeToString(dec) != hex.EncodeToString(plain) {
		t.Fatalf("decrypt mismatch:\ngot:  %s\nexp:  %s", hex.EncodeToString(dec), hex.EncodeToString(plain))
	}
}

func TestSM4RoundTrip(t *testing.T) {
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
	plaintext := []byte("Hello SM4! This is a test message for encryption.")

	block, err := cipher.NewSM4Block(key)
	if err != nil {
		t.Fatal(err)
	}

	padded := cipher.Pkcs7Padding(plaintext)
	enc := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		block.Encrypt(enc[i:i+16], padded[i:i+16])
	}

	dec := make([]byte, len(enc))
	for i := 0; i < len(enc); i += 16 {
		block.Decrypt(dec[i:i+16], enc[i:i+16])
	}

	unpadded, err := cipher.Pkcs7UnPadding(dec)
	if err != nil {
		t.Fatal(err)
	}
	if string(unpadded) != string(plaintext) {
		t.Fatalf("round trip mismatch:\ngot:  %q\nexp:  %q", string(unpadded), string(plaintext))
	}
}

func TestSM4AllZeroKey(t *testing.T) {
	key := make([]byte, 16)
	plain := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	block, err := cipher.NewSM4Block(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	block.Encrypt(out, plain)
	block.Decrypt(out, out)
	if hex.EncodeToString(out) != hex.EncodeToString(plain) {
		t.Fatalf("all-zero round trip failed")
	}
}

func TestSM4InvalidKeySize(t *testing.T) {
	_, err := cipher.NewSM4Block([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short key")
	}
}
