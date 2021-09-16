package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

type CipherRequest struct {
	Key string
}

func (cipher *CipherRequest) Encrypt(data string) (encrypted string, err error) {
	triplekey := cipher.Key + cipher.Key + cipher.Key
	// encrypt
	encryptedByte, err := TripleDesEncrypt([]byte(data), []byte(triplekey))
	encrypted = string(encryptedByte[:])
	return
}

func (cipher *CipherRequest) Decrypt(data string) (decrypted string, err error) {
	triplekey := cipher.Key + cipher.Key + cipher.Key
	// encrypt
	decryptedByte, err := TripleDesDecrypt([]byte(data), []byte(triplekey))
	decrypted = string(decryptedByte[:])
	return
}

func TripleDesEncrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := key
	iv := ciphertext[:des.BlockSize]
	origData := PKCS5Padding(data, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(origData))
	mode.CryptBlocks(encrypted, origData)
	return encrypted, nil
}

func TripleDesDecrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := key
	iv := ciphertext[:des.BlockSize]

	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	decrypter.CryptBlocks(decrypted, data)
	decrypted = PKCS5UnPadding(decrypted)
	return decrypted, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func main() {
	cipher := CipherRequest{"12345678"}
	encrypted, err := cipher.Encrypt("bukanana")
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}
