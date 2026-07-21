package cipher

import "fmt"

func Pkcs7Padding(data []byte) []byte {
	padLen := 16 - len(data)%16
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(data, padding...)
}

func Pkcs7UnPadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid data for unPadding")
	}
	padLen := int(data[len(data)-1])
	if padLen < 1 || padLen > 16 {
		return nil, fmt.Errorf("invalid padding length: %d", padLen)
	}
	for i := 1; i <= padLen; i++ {
		if data[len(data)-i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding content")
		}
	}
	return data[:len(data)-padLen], nil
}
