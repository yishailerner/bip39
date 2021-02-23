package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// NewEntropy reads and returns random entropy bytes from a secure
// source. bits specifies the number of bits to read. It must be
// between 128 and 256, and a multiple of 32.
func NewEntropy(bits int) ([]byte, error) {
	if err := checkEntropySize(bits); err != nil {
		return nil, err
	}

	entropy := make([]byte, bits/8)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	return entropy, nil
}

// Mnemonic encodes entropy to a mnemonic sentence - a group of easy
// to remember words, for the generation of deterministic wallets.
// entropy length must be between 128 and 256 bits, and a multiple of 32
// bits.
func Mnemonic(entropy []byte) (string, error) {
	if err := checkEntropySize(len(entropy) * 8); err != nil {
		return "", err
	}

	words := make([]string, len(entropy)*3/4)

	// append first len(entropy)/32 bits to initial entropy
	sum := sha256.Sum256(entropy)
	entropy = append(entropy, sum[:len(entropy)/4]...)

	br := newBitReader(entropy)
	for i := 0; i < len(words); i++ {
		word, err := br.ReadBits(11)
		if err != nil {
			return "", err
		}
		words[i] = wordlist[word]
	}
	return strings.Join(words, " "), nil
}

// Seed creates a binary seed from mnemonic, which can be protected with
// a passphrase. If a passphrase is not desired, an empty string may be
// used. The resulting seed can be later used to generate deterministic
// wallets using BIP-0032 or similar methods.
func Seed(mnemonic string, passphrase string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+passphrase), 2048, 64, sha512.New)
}

func checkEntropySize(bits int) error {
	if bits < 128 || bits > 256 {
		return errors.New("entropy must be 128 to 256 bits long")
	}
	if bits%32 != 0 {
		return errors.New("entropy size must be a multiple of 32 bits")
	}
	return nil
}

// Wordlist returns a copy of the wordlist used to generate mnemonics.
func Wordlist() []string {
	wl := make([]string, len(wordlist))
	copy(wl, wordlist)
	return wl
}
