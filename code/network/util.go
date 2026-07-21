package network

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func newUUID() string {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, 16)
	for i := range bytes {
		bytes[i] = byte(rng.Intn(256))
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

func randomMAC() string {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	mac := make([]byte, 6)
	for i := range mac {
		mac[i] = byte(rng.Intn(256))
	}
	mac[0] &^= 1
	parts := make([]string, 6)
	for i, b := range mac {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}
