package cipher

import "encoding/hex"

func toHex(data []byte) string {
	return hex.EncodeToString(data)
}

func fromHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func trimZeroTail(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i+1]
		}
	}
	return nil
}
