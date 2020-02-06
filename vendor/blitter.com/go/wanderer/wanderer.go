// Package wanderer - a crypto doodle that appears to give adequate
// protection to data in a stream cipher context
//
// Properties visualized using https://github.com/circulosmeos/circle
package wanderer

// TODOs:
// -define s-box rotation/shuffle schema
// -devise p-box schema (? Meh. Need to blockify & re-streamify to do this)
// ...

import (
	"errors"
	"fmt"
	"io"
	"time"

	mtwist "blitter.com/go/mtwist"
)

const (
	keylen    = 512
	sboxCount = keylen / 8
)

type Cipher struct {
	prng   *mtwist.MT19937_64
	r      io.Reader
	w      io.Writer
	k      []byte
	kidx   uint
	sboxen [][]byte
	sw     int
	sh     int
	sctr   int // TODO: used to count down to re-keying & sbox regen
	mode   int
	n      byte
}

// Given input byte x (treated as 2-bit dirs),
// 'walk' box applying XOR of each position (E/S/W/N) given box
// dimensions w,h
// NOTE to ensure reachability of all values within a box, w,h
// should not each exceed 3 and should probably stay at 2, to
// give more even coverage given random input.
func walkingXOR(key, s []byte, w, h int, x byte) (r byte) {
	i := 0
	r = x
	for sidx := range key {
		ktemp := key[sidx]
		r = r ^ (s[i])
		for shift := uint(0); shift < 8; shift += 2 {
			//			fmt.Println("i:", i, "r:", r)
			dir := (ktemp >> shift) & 0x03
			switch dir {
			case 0:
				i = i + 1
				i = i % len(s)
			case 1:
				i = i + w
				i = i % len(s)
			case 2:
				if i%w != 0 {
					i = i - 1
				} else {
					i = i + w - 1
				}
			case 3:
				if i >= w {
					i = i - w
				} else {
					i = len(s) + i - w
				}
			}
			r = r ^ (s[i])
		}
	}
	return
}

func (c *Cipher) genSBoxen(n uint) {
	c.sboxen = make([][]byte, n)
	var idx uint
	for ; idx < n; idx++ {
		c.sboxen[idx] = make([]byte, c.sw*c.sh)
		_, _ = c.prng.Read(c.sboxen[idx])
	}
	//fmt.Fprintf(os.Stderr, "sboxen[0]:%v\n", c.sboxen[0])
}

func New(r io.Reader, w io.Writer, mode int, key []byte, width, height int) (c *Cipher) {
	c = &Cipher{}
	c.prng = mtwist.New()
	if len(key) == 0 {
		c.k = []byte(fmt.Sprintf("%s", time.Now()))
	} else {
		c.k = key
	}
	c.prng.SeedFullState(c.k)

	// Discard first 64 bytes of MT output
	for idx := 0; idx < 64; idx++ {
		_ = c.prng.Int63()
	}
	c.mode = mode
	c.r = r
	c.w = w
	c.sw = width
	c.sh = height
	c.sctr = c.sw // sbox ctr: countdown to regen sboxes
	c.n = 0
	c.genSBoxen(sboxCount)

	//	fmt.Printf("%+v\n", sboxen)
	//	c.buf = make([]byte, 4)
	return c
}

func (c *Cipher) Read(p []byte) (n int, err error) {
	n, err = c.r.Read(p)
	if err == nil {
		for idx := 0; idx < n; idx++ {
			p[idx] = c.yield(p[idx])
		}
	}
	return n, err
}

func (c *Cipher) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	return n, err
}

// Mutate the session key (intended to be called as encryption
// proceeds), so that the 'walk path' through sboxes also does so.
func (c *Cipher) keyUpdate(perturb byte) {
	c.k[c.kidx] = c.k[c.kidx] ^ c.k[(c.kidx+1)%uint(len(c.k))]
	c.k[c.kidx] = c.k[c.kidx] ^ byte((c.prng.Int63()>>4)%256)
	c.kidx = (c.kidx + uint(perturb)) % uint(len(c.k))
	//for idx := 0; idx < len(c.k); idx++ {
	//	c.k[idx] = c.k[idx] ^ byte(c.prng.Int63() % 256)
	//}
}

// slow - perturb a single octet of a single sbox for each octet
// (CV = ~8.725% over 700 MiB of 0-byte pt)
func (c *Cipher) sboxUpdateA(perturb byte) {
	c.sboxen[perturb%sboxCount][int(perturb)%(c.sw+c.sh)] ^=
		perturb
}

// slower - perturb a single sbox for each octet
// (CV = ~5.6369% over 700 MiB of 0-byte pt)
func (c *Cipher) sboxUpdateB(perturb byte) {
	lim := c.sw * c.sh
	for idx := 0; idx < lim; idx++ {
		c.sboxen[perturb%sboxCount][idx] ^= perturb
	}
}

// slowest -- full sbox re-gen after each octet
// (but lowest CV, ~0.0554% over 700MiB of 0-byte pt)
func (c *Cipher) sboxUpdateC(perturb byte) {
	c.genSBoxen(sboxCount)
	//c.sboxen[perturb%sboxCount][int(perturb)%(c.sw+c.sh)] ^=
	//	perturb
}

func (c *Cipher) yield(ib byte) (ob byte) {
	ob = walkingXOR(c.k, c.sboxen[c.n], c.sw, c.sh, ib)
	c.n = (c.n + 1) % byte(len(c.sboxen))
	c.keyUpdate(ob ^ ib) // must be equal in either encrypt/decrypt dirs
	switch c.mode {
	case 0:
		// [nothing - varA]
		break
	case 1:
		c.sboxUpdateA(ob ^ ib) // varA
	case 2:
		c.sboxUpdateB(ob ^ ib) // varB
	case 3:
		c.sboxUpdateC(ob ^ ib) // varC
	default:
		// [nothing]
	}
	//	c.sctr = c.sctr - 1
	//	if c.sctr == 0 {
	//		c.genSBoxen(sboxCount)
	//		c.sctr = c.sw
	//	}
	return ob
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
	//fmt.Printf("len dst:%d len src:%d\n", len(dst), len(src))
	if len(dst) < len(src) {
		panic(errors.New("len(dst) < len(src)"))
	}

	for idx, v := range src {
		dst[idx] = c.yield(v)
	}
}
