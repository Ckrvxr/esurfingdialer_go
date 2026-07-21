package tests

import (
	"testing"

	"esurfingdialer/code/cipher"
)

func TestFactoryAllAlgorithms(t *testing.T) {
	algos := []struct {
		uuid string
		name string
	}{
		{"CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E", "AESCBC"},
		{"A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4", "AESECB"},
		{"5BFBA864-BBA9-42DB-8EAD-49B5F412BD81", "DESedeCBC"},
		{"6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5", "DESedeECB"},
		{"B809531F-0007-4B5B-923B-4BD560398113", "ZUC"},
		{"F3974434-C0DD-4C20-9E87-DDB6814A1C48", "SM4CBC"},
		{"ED382482-F72C-4C41-A76D-28EEA0F1F2AF", "SM4ECB"},
		{"B3047D4E-67DF-4864-A6A5-DF9B9E525C79", "ModXTEA"},
		{"C32C68F9-CA81-4260-A329-BBAFD1A9CCD1", "ModXTEAIV"},
	}

	for _, a := range algos {
		ciph, err := cipher.GetInstance(a.uuid)
		if err != nil {
			t.Fatalf("GetInstance(%s) failed: %v", a.uuid, err)
		}
		plaintext := "Hello from " + a.name + "!"
		enc := ciph.Encrypt(plaintext)
		dec := ciph.Decrypt(enc)
		if dec != plaintext {
			t.Fatalf("%s round trip failed:\ngot:  %q\nexp:  %q", a.name, dec, plaintext)
		}
	}
}

func TestFactoryUnknownAlgo(t *testing.T) {
	_, err := cipher.GetInstance("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}
