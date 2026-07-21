package cipher

import (
	"testing"
)

func TestPkcs7Padding(t *testing.T) {
	tests := []struct {
		input    []byte
		padLen   int
		expected int
	}{
		{[]byte{}, 16, 16},
		{[]byte{1}, 16, 16},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 16, 16},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 16, 32},
	}

	for _, tt := range tests {
		padded := Pkcs7Padding(tt.input)
		if len(padded) != tt.expected {
			t.Errorf("padding len: got %d, exp %d for input len %d", len(padded), tt.expected, len(tt.input))
		}
		unpadded, err := Pkcs7UnPadding(padded)
		if err != nil {
			t.Errorf("unpadding error: %v", err)
		}
		if len(unpadded) != len(tt.input) {
			t.Errorf("unpadded len: got %d, exp %d", len(unpadded), len(tt.input))
		}
		for i := range tt.input {
			if unpadded[i] != tt.input[i] {
				t.Errorf("byte %d: got %02x, exp %02x", i, unpadded[i], tt.input[i])
			}
		}
	}
}

func TestPkcs7InvalidData(t *testing.T) {
	_, err := Pkcs7UnPadding([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}

	_, err = Pkcs7UnPadding([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for invalid padding")
	}
}
