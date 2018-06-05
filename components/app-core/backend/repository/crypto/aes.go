package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	log "github.com/Sirupsen/logrus"
)

// Encrypt - Encrypt a token based on an encryption key
// The approach used here is based on the following direction on how to AES
// encrypt/decrypt our secret information, in this case tokens (normal, refresh
// and OAuth tokens).
// Source: https://github.com/giorgisio/examples/blob/master/aes-encrypt/main.go
func Encrypt(key, text []byte) (ciphertext []byte, err error) {
	log.Debug("Encrypt")
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(string(text)))

	// iv =  initialization vector
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)

	return
}

// Decrypt - Decrypt a token based on an encryption key
// The approach used here is based on the following direction on how to AES
// encrypt/decrypt our secret information, in this case tokens (normal, refresh
// and OAuth tokens).
// Source: https://github.com/giorgisio/examples/blob/master/aes-encrypt/main.go
func Decrypt(key, ciphertext []byte) (plaintext []byte, err error) {
	log.Debug("Decrypt")

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}

// ReadEncryptionKey - Read the encryption key from the shared volume
func ReadEncryptionKey(v, f string, expectedKeyLength int) ([]byte, error) {
	log.Println("ReadEncryptionKey")

	// TODO: I don't understand what these next few lines do, but it's a simpler
	// refactor than how they used to work.
	encryptionKeyPath := fmt.Sprintf("/%s/%s", v, f)
	if strings.HasPrefix(f, "/") {
		encryptionKeyPath = encryptionKeyPath[1:]
	}

	keyHexEncoded, err := ioutil.ReadFile(encryptionKeyPath)
	if err != nil {
		log.Errorf("Unable to read encryption key file: %+v\n", err)
		return nil, err
	}

	keyBytes, err := hex.DecodeString(string(keyHexEncoded))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	if len(keyBytes) != expectedKeyLength {
		log.Errorf("expected encryption key to be %d bytes, instead: %d", expectedKeyLength, len(keyBytes))
		return nil, errors.New("unexpected key length")
	}

	return keyBytes, nil
}
