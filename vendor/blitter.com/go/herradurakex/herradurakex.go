// Package hkex - an experimental key exchange algorithm
// by Omar Alejandro Herrera Reyna.
//
// (https://github.com/Caume/HerraduraKEx)
//
// The core HerraduraKEx algorithm is dual-licensed
// by the author (Omar Alejandro Herrera Reyna)
// under GPL3 and MIT licenses.
// See LICENSE.gpl and LICENSE.mit in this distribution
//
// Go implementation Copyright (c) 2017-2018 Russell Magee
// (rmagee_at_gmail_com)
// Licensed under the terms of the MIT license
// See LICENSE.mit in this distribution
package hkex

/*  Herradura - a Key exchange scheme in the style of Diffie-Hellman Key Exchange.
    Copyright (C) 2017 Omar Alejandro Herrera Reyna

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    golang implementation by Russ Magee (rmagee_at_gmail.com) */

/* This is the core KEx algorithm. For client/server net support code,
See the hkexnet package (currently a sub-package of hkexsh) for a
golang/pkg/net compatible Conn interface using this to negotiate keys and
secure a network channel. */

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

// HerraduraKEx holds the session state for a key exchange.
type HerraduraKEx struct {
	intSz, pubSz int
	randctx      *rand.Rand
	a            *big.Int
	b            *big.Int
	d, peerD     *big.Int
	fa           *big.Int
}

// New returns a HerraduraKEx struct.
//
//   i - internal (private) random nonce
//   p - public (exchanged) random nonce (typically 1/4 bitsize of i)
//
//   If i or p are passed as zero, they will default to 256 and 64,
//   respectively.
func New(i int, p int) (h *HerraduraKEx) {
	h = new(HerraduraKEx)

	if i == 0 {
		i = 256
	}
	if p == 0 {
		p = 64
	}

	h.intSz = i
	h.pubSz = p

	h.seed()
	h.a = h.rand()
	h.b = h.rand()

	h.d = h.fscxRevolve(h.a, h.b, h.pubSz)
	return h
}

func (h *HerraduraKEx) seed() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	h.randctx = r
}

func (h *HerraduraKEx) rand() (v *big.Int) {
	v = big.NewInt(0)
	v.Rand(h.randctx, h.getMax())
	return v
}

// getMax returns the max value for an n-bit big.Int
func (h *HerraduraKEx) getMax() (n *big.Int) {
	n = big.NewInt(0)
	var max big.Int

	for i := 0; i < h.intSz; i++ {
		max.SetBit(n, i, 1)
	}
	n = &max
	return n
}

func (h *HerraduraKEx) bitX(x *big.Int, pos int) (ret int64) {
	if pos < 0 {
		pos = h.intSz - pos
	}

	if pos == 0 {
		ret = int64(x.Bit(1) ^ x.Bit(0) ^ x.Bit(h.intSz-1))
	} else if pos == h.intSz-1 {
		ret = int64(x.Bit(0) ^ x.Bit(pos) ^ x.Bit(pos-1))
	} else {
		ret = int64(x.Bit((pos+1)%h.intSz) ^ x.Bit(pos) ^ x.Bit(pos-1))
	}
	return ret
}

func (h *HerraduraKEx) bit(up, down *big.Int, posU, posD int) (ret *big.Int) {
	return big.NewInt(h.bitX(up, posU) ^ h.bitX(down, posD))
}

func (h *HerraduraKEx) fscx(up, down *big.Int) (result *big.Int) {
	result = big.NewInt(0)

	for count := 0; count < h.intSz; count++ {
		result.Lsh(result, 1)
		result.Add(result, h.bit(up, down, count, count))
	}
	return result
}

// This is the iteration function using the result of the previous iteration
// as the first parameter and the second parameter of the first iteration.
func (h *HerraduraKEx) fscxRevolve(x, y *big.Int, passes int) (result *big.Int) {
	result = x
	for count := 0; count < passes; count++ {
		result = h.fscx(result, y)
	}
	return result
}

// D returns the D (FSCX Revolved) value, input to generate FA
// (the value for peer KEx)
func (h HerraduraKEx) D() *big.Int {
	return h.d
}

// PeerD returns the peer D value
func (h HerraduraKEx) PeerD() *big.Int {
	return h.peerD
}

// SetPeerD stores the received peer's D value (contents, not ptr)
func (h *HerraduraKEx) SetPeerD(pd *big.Int) {
	h.peerD = new(big.Int).Set(pd)
}

// ComputeFA computes the FA value, which must be sent to peer for KEx.
func (h *HerraduraKEx) ComputeFA() {
	h.fa = h.fscxRevolve(h.peerD, h.b, h.intSz-h.pubSz)
	h.fa.Xor(h.fa, h.a)
}

// FA returns the computed FA value
func (h HerraduraKEx) FA() *big.Int {
	return h.fa
}

// Output HerraduraKEx type value as a string. Implements Stringer interface.
func (h *HerraduraKEx) String() string {
	return fmt.Sprintf("s:%d p:%d\na:%s\nb:%s\nd:->%s\n<-peerD:%s\nfa:%s",
		h.intSz, h.pubSz,
		h.a.Text(16), h.b.Text(16),
		h.d.Text(16),
		h.peerD.Text(16),
		h.fa.Text(16))
}
