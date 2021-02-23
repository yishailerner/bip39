package bip39

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEntropyValidation(t *testing.T) {
	t.Parallel()

	for bits := 128; bits <= 256; bits += 32 {
		if _, err := NewEntropy(bits); err != nil {
			t.Errorf("NewEntropy(%d) = %v, expected nil", bits, err)
		}
	}
	for bits := 0; bits < 500; bits++ {
		if bits%32 != 0 {
			if _, err := NewEntropy(bits); err == nil {
				t.Errorf("NewEntropy(%d) = nil, expected error", bits)
			}
		}
	}
}

func TestMnemonic(t *testing.T) {
	t.Parallel()

	for _, test := range vectors(t) {
		mnemonic, err := Mnemonic(test.Entropy)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(test.Mnemonic, mnemonic); diff != "" {
			t.Fatal("mnemonics are different (-want +got)\n", diff)
		}
	}
}

var mnemonic string

func BenchmarkMnemonic(b *testing.B) {
	entropy, err := NewEntropy(256)
	if err != nil {
		b.Fatal(err)
	}

	var m string
	for n := 0; n < b.N; n++ {
		m, err = Mnemonic(entropy)
		if err != nil {
			b.Fatal(err)
		}
	}
	mnemonic = m
}

func TestSeed(t *testing.T) {
	t.Parallel()

	for _, test := range vectors(t) {
		seed := Seed(test.Mnemonic, "TREZOR")
		if diff := cmp.Diff([]byte(test.Seed), seed); diff != "" {
			t.Fatal("seeds are different (-want +got)\n", diff)
		}
	}
}

var (
	mu          sync.Mutex // guards vectorCache
	vectorCache []vector
)

func vectors(t *testing.T) []vector {
	mu.Lock()
	defer mu.Unlock()

	if vectorCache == nil {
		f, err := os.Open("testdata/vectors.json")
		if err != nil {
			t.Fatal(err)
		}

		if err := json.NewDecoder(f).Decode(&vectorCache); err != nil {
			t.Fatal(err)
		}
	}
	return vectorCache
}

type vector struct {
	Entropy  hexField `json:"entropy"`
	Mnemonic string   `json:"mnemonic"`
	Seed     hexField `json:"seed"`
}

type hexField []byte

func (h *hexField) UnmarshalJSON(b []byte) error {
	var hexEncoded string
	if err := json.Unmarshal(b, &hexEncoded); err != nil {
		return err
	}
	result, err := hex.DecodeString(hexEncoded)
	if err != nil {
		return err
	}
	*h = result
	return nil
}
