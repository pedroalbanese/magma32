//Use it with caution.
//Exaple echo 21,474,836.48|magma32 -key $256bitkey | magma32 -key $256bitkey -unobfuscate -decimal
package main

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pedroalbanese/gogost/gost341264"
)

// MAGMAObfuscator is an integer obfuscator that uses MAGMA as the block cipher
type MAGMAObfuscator struct {
	block cipher.Block
}

// NewMAGMAObfuscator creates a new MAGMAObfuscator with the provided Magma key.
// The key must be 32 bytes.
func NewMAGMAObfuscator(key []byte) (*MAGMAObfuscator, error) {
	block := gost341264.NewCipher(key)
	return &MAGMAObfuscator{block: block}, nil
}

// Obfuscate obfuscates an integer using MAGMA encryption
func (o *MAGMAObfuscator) Obfuscate(id uint32) ([]byte, error) {
	plaintext := make([]byte, 4)
	binary.BigEndian.PutUint32(plaintext, id)

	// Pad the plaintext to the block size
	paddedPlaintext := make([]byte, o.block.BlockSize())
	copy(paddedPlaintext, plaintext)

	ciphertext := make([]byte, len(paddedPlaintext))
	o.block.Encrypt(ciphertext, paddedPlaintext)

	return ciphertext, nil
}

// Unobfuscate unobfuscates an integer using MAGMA decryption
func (o *MAGMAObfuscator) Unobfuscate(ciphertext []byte) (uint32, error) {
	if len(ciphertext) != o.block.BlockSize() {
		return 0, errors.New("Invalid ciphertext length")
	}

	plaintext := make([]byte, len(ciphertext))
	o.block.Decrypt(plaintext, ciphertext)

	return binary.BigEndian.Uint32(plaintext[:4]), nil
}

func main() {
	unobfuscateFlag := flag.Bool("unobfuscate", false, "Unobfuscate mode")
	decimalFlag := flag.Bool("decimal", false, "Decimal flag")
	key := flag.String("key", "", "Key")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)

	if *unobfuscateFlag {
		// Read ciphertext from stdin
		ciphertextStr, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		ciphertextStr = strings.TrimSpace(ciphertextStr)

		// Decode ciphertext from hexadecimal
		ciphertext, err := hex.DecodeString(ciphertextStr)
		if err != nil {
			panic(err)
		}

		// Example usage
		mkey, err := hex.DecodeString(*key)
		if err != nil {
			panic(err)
		}
		obfuscator, err := NewMAGMAObfuscator(mkey)
		if err != nil {
			panic(err)
		}

		// Unobfuscate the ciphertext
		decryptedID, err := obfuscator.Unobfuscate(ciphertext)
		if err != nil {
			panic(err)
		}

		if *decimalFlag {
			// Convert to decimal format
			amount := float64(decryptedID) / 100
			fmt.Printf("%.2f\n", amount)
		} else {
			// Output the decrypted ID to stdout
			fmt.Println(decryptedID)
		}
	} else {
		// Read amount from stdin
		amountStr, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		amountStr = strings.TrimSpace(amountStr)
		amountStr = strings.ReplaceAll(amountStr, ",", "")
		amountStr = strings.ReplaceAll(amountStr, ".", "")

		var amount uint64
		amount, err = strconv.ParseUint(amountStr, 10, 32)
		if err != nil {
			panic(err)
		}

		// Example usage
		mkey, err := hex.DecodeString(*key)
		if err != nil {
			panic(err)
		}
		obfuscator, err := NewMAGMAObfuscator(mkey)
		if err != nil {
			panic(err)
		}

		// Obfuscate an integer
		ciphertext, err := obfuscator.Obfuscate(uint32(amount))
		if err != nil {
			panic(err)
		}

		// Output the ciphertext to stdout
		fmt.Printf("%x\n", ciphertext)
	}
}
