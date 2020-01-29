// MersenneTwister
// From https://gist.github.com/cuixin/1b8b6bd7bfbde8fe76e8
package MersenneTwister

import (
	"crypto"

	_ "crypto/sha512"
)

const N = 312
const M = 156
const MATRIX_A = 0xB5026F5AA96619E9
const UPPER_MASK = 0xFFFFFFFF80000000
const LOWER_MASK = 0x7FFFFFFF

type MT19937_64 struct {
	array [N]uint64 //state vector
	index uint64    // array index
}

func New() *MT19937_64 {
	return &MT19937_64{
		index: N + 1,
	}
}

func (m *MT19937_64) _initstate() {
	// Recommendations abound that mtwist should throw away 1st 10000 or so
	// of initial state
	for i := 0; i < 10000; i++ {
		_ = m.Int63()
	}
}

func (m *MT19937_64) Seed(seed int64) {
	m.array[0] = uint64(seed)
	for m.index = 1; m.index < N; m.index++ {
		m.array[m.index] = (6364136223846793005*(m.array[m.index-1]^(m.array[m.index-1]>>62)) + m.index)
	}
	m._initstate()
	//fmt.Printf("final array(s):%v\n", m.array)
}

func _bytesToUint64(b []byte) (r uint64) {
	r = uint64(b[0])<<56 +
		uint64(b[1])<<48 +
		uint64(b[2])<<40 +
		uint64(b[3])<<32 +
		uint64(b[4])<<24 +
		uint64(b[5])<<16 +
		uint64(b[6])<<8 +
		uint64(b[7])
	return
}

func (m *MT19937_64) SeedFullState(s []byte) {
	//fmt.Printf("s:%v\n", s)
	if len(s) < N*8 {
		// Expand s if shorter than mtwist array state
		ha := crypto.SHA512
		h := ha.New()
		shortfallChunks := ((N * 8) - len(s)) / h.Size()
		//shortfallRem := ((N * 8) - len(s)) % h.Size()
		//fmt.Printf("chunks, rem:%d,%d\n", shortfallChunks, shortfallRem)
		idx := 0
		for idx < shortfallChunks {
			_, _ = h.Write(s)
			s = h.Sum(s)
			idx += 1
		}
		_, _ = h.Write(s)
		s = h.Sum(s)
		//fmt.Printf("exp s:%v\n", s)
	}

	for idx := 0; idx < N; {
		m.array[idx] = _bytesToUint64(s[idx*8 : (idx*8)+8])
		idx += 1
	}
	//fmt.Printf("final array(xs):%v\n", m.array)
	m.index = 0
	m._initstate()
}

func (m *MT19937_64) Int63() uint64 {
	var i int
	var x uint64
	mag01 := []uint64{0, MATRIX_A}
	if m.index >= N {
		if m.index == N+1 {
			m.Seed(int64(5489))
		}

		for i = 0; i < N-M; i++ {
			x = (m.array[i] & UPPER_MASK) | (m.array[i+1] & LOWER_MASK)
			m.array[i] = m.array[i+(M)] ^ (x >> 1) ^ mag01[int(x&uint64(1))]
		}
		for ; i < N-1; i++ {
			x = (m.array[i] & UPPER_MASK) | (m.array[i+1] & LOWER_MASK)
			m.array[i] = m.array[i+(M-N)] ^ (x >> 1) ^ mag01[int(x&uint64(1))]
		}
		x = (m.array[N-1] & UPPER_MASK) | (m.array[0] & LOWER_MASK)
		m.array[N-1] = m.array[M-1] ^ (x >> 1) ^ mag01[int(x&uint64(1))]
		m.index = 0
	}
	x = m.array[m.index]
	m.index++
	x ^= (x >> 29) & 0x5555555555555555
	x ^= (x << 17) & 0x71D67FFFEDA60000
	x ^= (x << 37) & 0xFFF7EEE000000000
	x ^= (x >> 43)
	return x
}

func (m *MT19937_64) IntN(value uint64) uint64 {
	return m.Int63() % value
}

func (m *MT19937_64) Read(p []byte) (n int, err error) {
	for idx := 0; idx < len(p); idx++ {
		p[idx] = byte( (m.Int63()>>47) % 256)
	}
	return n, nil
}
