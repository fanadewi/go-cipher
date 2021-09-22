package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	Service "github.com/fanadewi/go-cipher/services"
)

func main() {
	aes256()
	tripleDes()
}

func tripleDes() {
	fmt.Println("TripleDes")
	tripleDesCipher := Service.TripleDesCipher{Key: generateKey(4)}
	encrypted, err := tripleDesCipher.Encrypt("tripleDesAna")
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
	decrypted, err := tripleDesCipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}

func aes256() {
	fmt.Println("AES")
	aes256Cipher := Service.Aes256Cipher{Key: generateKey(32)}
	encrypted, err := aes256Cipher.Encrypt("AesExampleAna")
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)

	decrypted, err := aes256Cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}

func generateKey(byteSize int) string {
	bytes := make([]byte, byteSize)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}
	key := hex.EncodeToString(bytes) //encode key in bytes to string and keep as secret, put in a vault
	return key
}
