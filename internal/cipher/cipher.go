package cipher

type Interface interface {
	Encrypt(text string) string
	Decrypt(hex string) string
}
