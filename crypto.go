package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func computeHmac512(src string, secret string) string {
	h := hmac.New(sha512.New, []byte(secret))
	h.Write([]byte(src))
	shaStr := fmt.Sprintf("%x", h.Sum(nil))
	return shaStr
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func ComparePassword(hashedPass, givenPass string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(givenPass))
	return err == nil
}

func Base64Decode(input string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func RSADecrypt(ciphertext string, priv *rsa.PrivateKey) string {
	cipherBytes, _ := base64.StdEncoding.DecodeString(ciphertext)
	plaintext, _ := rsa.DecryptPKCS1v15(rand.Reader, priv, cipherBytes)
	return string(plaintext)
}

func EncryptAES(encKey, iv, text string) string {
	bKey := []byte(encKey)
	bText := []byte(text)
	bIV := []byte(iv)

	block, err := aes.NewCipher(bKey)
	if err != nil {
		return ""
	}

	bText = PKCS7Padding(bText, block.BlockSize())

	blockModel := cipher.NewCBCEncrypter(block, bIV[:block.BlockSize()])
	ciphertext := make([]byte, len(bText))
	blockModel.CryptBlocks(ciphertext, bText)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func DecryptAES(encKey, iv, cipherText string) string {

	bKey := []byte(encKey)
	bIV := []byte(iv)

	bCipher, _ := base64.StdEncoding.DecodeString(cipherText)

	block, err := aes.NewCipher(bKey)
	if err != nil {
		return ""
	}

	blockModel := cipher.NewCBCDecrypter(block, bIV[:block.BlockSize()])
	plantText := make([]byte, len(bCipher))
	blockModel.CryptBlocks(plantText, bCipher)
	plantText, err = PKCS7UnPadding(plantText)
	if err != nil {
		return ""
	}
	return string(plantText)
}

func PKCS7UnPadding(plantText []byte) ([]byte, error) {
	length := len(plantText)
	if length <= 0 {
		return nil, nil
	}
	unpadding := int(plantText[length-1])
	effectiveCount := length - unpadding
	if effectiveCount <= 0 {
		return nil, nil
	}
	return plantText[:effectiveCount], nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func GetPrivateKey(in string) (*rsa.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return nil, err
	}

	return GetPriKeyFromPem(key)
}

func GetPriKeyFromPem(pub []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, nil
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}

	return pri, nil
}
