// Package CryptMT - implementation of cryptMTv1 stream cipher
// (but with mtwist64 as base accum) 
// https://eprint.iacr.org/2005/165.pdf 
package cryptmt

// TODO rlm: according to go docs, stream ciphers do not implement the
// cipher.Block interface at all (thus do not support Encrypt() or
// Decrypt() .. cipher.StreamReader/StreamWriter() only call
// XORKeyStream() anyhow and for my own purposes this is all that is
// required.

import (
	"errors"

	mtwist "blitter.com/go/mtwist"
)

type Cipher struct {
	accum uint64
	m     *mtwist.MT19937_64
}

func (c *Cipher) yield() (r byte) {
	c.accum = c.accum * (c.m.Int63() | 1)
	r = byte(c.accum>>56) & 0xFF
	return
}

// New creates and returns a Cipher. The key argument should be the
// CryptMT key, 64 bytes.
func New(key []byte) (c *Cipher) {
	c = &Cipher{m: mtwist.New()}
	c.m.SeedFullState(key)
	c.accum = 1
	// from paper, discard first 64 bytes of output
	for idx := 0; idx < 64; idx++ {
		_ = c.yield()
	}
	return c
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src must overlap entirely or not at all.
//
// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
//
// Multiple calls to XORKeyStream behave as if the concatenation of
// the src buffers was passed in a single run. That is, Stream
// maintains state and does not reset at each XORKeyStream call.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic(errors.New("len(dst) < len(src)"))
	}

	for i, b := range src {
		dst[i] = b ^ c.yield()
	}
}
