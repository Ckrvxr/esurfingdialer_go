package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func GetTime() string {
	loc := time.FixedZone("CST", 8*3600)
	now := time.Now().In(loc)
	return now.Format("2006-01-02 15:04:05")
}

func RandomMACAddress() string {
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

func RandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rng.Intn(len(charset))]
	}
	return string(result)
}

func MD5Hex(data string) string {
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}
