package client

import (
	"fmt"
	"os"

	appcipher "esurfingdialer/internal/cipher"
	"esurfingdialer/internal/network"
	"esurfingdialer/internal/utils"
)

type Session struct {
	initialized bool
	cipher      appcipher.Interface
}

var session = &Session{}

func (s *Session) IsInitialized() bool {
	return s.initialized
}

func (s *Session) Initialize(zsm []byte) {
	utils.Print("🔐 Initializing session...")
	s.initialized = s.load(zsm)
}

func (s *Session) load(zsm []byte) bool {
	if len(zsm) < 4 {
		utils.Print("⚠️ Invalid ZSM header")
		return false
	}

	header := string(zsm[:3])
	pos := 4
	keyLen := int(zsm[3])
	if pos+keyLen > len(zsm) {
		utils.Print("⚠️ Invalid key length")
		return false
	}

	pos += keyLen
	if pos >= len(zsm) {
		utils.Print("⚠️ Invalid algo ID length")
		return false
	}

	algoIDLen := int(zsm[pos])
	pos++

	if pos+algoIDLen > len(zsm) {
		utils.Print("⚠️ Invalid algo ID")
		return false
	}

	algoID := string(zsm[pos : pos+algoIDLen])
	ciph, err := appcipher.GetInstance(algoID)
	if err != nil {
		utils.Print("⚠️ Algorithm init failed: " + err.Error())
		s.saveBytesToFile(fmt.Sprintf("algo_dump_%d.bin", timeNowUnix()), zsm)
		return false
	}

	network.States.SetAlgoID(algoID)
	s.cipher = ciph

	utils.Print("📦 Cipher: " + algoID + " (" + header + ")")

	return true
}

func (s *Session) Encrypt(text string) string {
	return s.cipher.Encrypt(text)
}

func (s *Session) Decrypt(hex string) string {
	return s.cipher.Decrypt(hex)
}

func (s *Session) Free() {
	s.initialized = false
}

func IsSessionInitialized() bool {
	return session.IsInitialized()
}

func FreeSession() {
	session.Free()
}

func (s *Session) saveBytesToFile(fileName string, data []byte) {
	if err := os.WriteFile(fileName, data, 0644); err != nil {
		utils.Print("⚠️ Failed to write dump file: " + err.Error())
	}
}
