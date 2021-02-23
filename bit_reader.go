package bip39

import (
	"bytes"
	"io"
)

// NOTE: taken from compress/bzip2

// bitReader wraps an io.Reader and provides the ability to read values,
// bit-by-bit, from it. Its Read* methods don't return the usual error
// because the error handling was verbose. Instead, any error is kept and can
// be checked afterwards.
type bitReader struct {
	r    io.ByteReader
	n    uint64
	bits uint
}

// newBitReader returns a new bitReader reading from r. If r is not
// already an io.ByteReader, it will be converted via a bufio.Reader.
func newBitReader(b []byte) bitReader {
	br := bytes.NewReader(b)
	return bitReader{r: br}
}

// ReadBits reads the given number of bits and returns them in the
// least-significant part of a uint64.
func (br *bitReader) ReadBits(bits uint) (n uint64, err error) {
	var b byte
	for bits > br.bits {
		b, err = br.r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return
		}
		br.n <<= 8
		br.n |= uint64(b)
		br.bits += 8
	}

	// br.n looks like this (assuming that br.bits = 14 and bits = 6):
	// Bit: 111111
	//      5432109876543210
	//
	//         (6 bits, the desired output)
	//        |-----|
	//        V     V
	//      0101101101001110
	//        ^            ^
	//        |------------|
	//           br.bits (num valid bits)
	//
	// This the next line right shifts the desired bits into the
	// least-significant places and masks off anything above.
	n = (br.n >> (br.bits - bits)) & ((1 << bits) - 1)
	br.bits -= bits
	return
}
