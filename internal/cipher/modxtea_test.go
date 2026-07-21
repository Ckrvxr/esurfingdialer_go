package cipher

import (
	"testing"
)

var testMKey1 = []int32{0x7A7A676A, 662588019, 1044588908, 1467841914}
var testMKey2 = []int32{1027369311, 1903786612, 1147098979, 1869162341}
var testMKey3 = []int32{1532651581, 777464439, 1246184549, 1715306076}
var testMIV = []int32{1414278975, 1867010337}

func TestModXTEARoundTrip(t *testing.T) {
	plaintext := "Hello ModXTEA! This is a test message."

	ciph := NewModXTEA(testMKey1, testMKey2, testMKey3)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)

	if dec != plaintext {
		t.Fatalf("ModXTEA round trip failed:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}

func TestModXTEAEmpty(t *testing.T) {
	ciph := NewModXTEA(testMKey1, testMKey2, testMKey3)
	enc := ciph.Encrypt("")
	dec := ciph.Decrypt(enc)
	if dec != "" {
		t.Fatalf("empty string round trip failed: %q", dec)
	}
}

func TestModXTEAExact8Bytes(t *testing.T) {
	plaintext := "12345678"

	ciph := NewModXTEA(testMKey1, testMKey2, testMKey3)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)

	if dec != plaintext {
		t.Fatalf("8-byte block round trip failed:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}

func TestModXTEAIVRoundTrip(t *testing.T) {
	plaintext := "Hello ModXTEAIV! Testing with IV."

	ciph := NewModXTEAIV(testMKey1, testMKey2, testMKey3, testMIV)
	enc := ciph.Encrypt(plaintext)
	dec := ciph.Decrypt(enc)

	if dec != plaintext {
		t.Fatalf("ModXTEAIV round trip failed:\ngot:  %q\nexp:  %q", dec, plaintext)
	}
}

func TestModXTEAIVEmpty(t *testing.T) {
	ciph := NewModXTEAIV(testMKey1, testMKey2, testMKey3, testMIV)
	enc := ciph.Encrypt("")
	dec := ciph.Decrypt(enc)
	if dec != "" {
		t.Fatalf("empty string round trip failed: %q", dec)
	}
}

func TestModXTEAEncryptDeterministic(t *testing.T) {
	ciph1 := NewModXTEA(testMKey1, testMKey2, testMKey3)
	ciph2 := NewModXTEA(testMKey1, testMKey2, testMKey3)

	r1 := ciph1.Encrypt("test")
	r2 := ciph2.Encrypt("test")
	if r1 != r2 {
		t.Fatalf("deterministic encryption failed:\n1: %s\n2: %s", r1, r2)
	}
}

func TestModXTEAKeyPanicsOnShortKey(t *testing.T) {
	shortKey := []int32{1, 2, 3}
	ciph := NewModXTEA(shortKey, testMKey2, testMKey3)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for short key but got none")
		}
	}()
	ciph.Encrypt("test")
}
