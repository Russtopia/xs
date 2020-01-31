// xsnet.go - net.Conn compatible channel setup with encrypted/HMAC
// negotiation

// Copyright (c) 2017-2019 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

package xsnet

// Implementation of HKEx-wrapped versions of the golang standard
// net package interfaces, allowing clients and servers to simply replace
// 'net.Dial' and 'net.Listen' with 'hkex.Dial' and 'hkex.Listen'
// (though some extra methods are implemented and must be used
//  for things outside of the scope of plain sockets).

// DESIGN PRINCIPLE: There shall be no protocol features which enable
// downgrade attacks. The server shall have final authority to accept or
// reject any and all proposed KEx and connection parameters proposed by
// clients at setup. Action on denial shall be a simple server disconnect
// with possibly a status code sent so client can determine why connection
// was denied (compare to how failed auth is communicated to client).

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	hkex "blitter.com/go/herradurakex"
	"blitter.com/go/xs/logger"
	"blitter.com/go/kyber"
	"blitter.com/go/newhope"
)

/*---------------------------------------------------------------------*/
const PAD_SZ = 32     // max size of padding applied to each packet
const HMAC_CHK_SZ = 4 // leading bytes of HMAC to xmit for verification

type (
	WinSize struct {
		Rows uint16
		Cols uint16
	}

	// chaffconfig captures attributes used to send chaff packets betwixt
	// client and server connections, to obscure true traffic timing and
	// patterns
	// see: https://en.wikipedia.org/wiki/chaff_(countermeasure)
	ChaffConfig struct {
		shutdown bool //set to inform chaffHelper to shut down
		enabled  bool
		msecsMin uint //msecs min interval
		msecsMax uint //msecs max interval
		szMax    uint // max size in bytes
	}

	// Conn is a connection wrapping net.Conn with KEX & session state
	Conn struct {
		kex KEXAlg // KEX/KEM proposal (client -> server)

		m *sync.Mutex // (internal)
		c *net.Conn   // which also implements io.Reader, io.Writer, ...

		logCipherText  bool // somewhat expensive, for debugging
		logPlainText   bool // INSECURE and somewhat expensive, for debugging
		logTunActivity bool

		cipheropts uint32 // post-KEx cipher/hmac options
		opts       uint32 // post-KEx protocol options (caller-defined)
		WinCh      chan WinSize
		Rows       uint16
		Cols       uint16

		chaff ChaffConfig
		tuns  *map[uint16](*TunEndpoint)

		closeStat *CSOType      // close status (CSOExitStatus)
		r         cipher.Stream //read cipherStream
		rm        hash.Hash
		w         cipher.Stream //write cipherStream
		wm        hash.Hash
		dBuf      *bytes.Buffer //decrypt buffer for Read()
	}
)

var (
	Log *logger.Writer // reg. syslog output (no -d)
)

// Return string (suitable as map key) for a tunnel endpoint
func (t *TunEndpoint) String() string {
	return fmt.Sprintf("[%d:%s:%d]", t.Lport, t.Peer, t.Rport)
}

func (k *KEXAlg) String() string {
	switch *k {
	case KEX_HERRADURA256:
		return "KEX_HERRADURA256"
	case KEX_HERRADURA512:
		return "KEX_HERRADURA512"
	case KEX_HERRADURA1024:
		return "KEX_HERRADURA1024"
	case KEX_HERRADURA2048:
		return "KEX_HERRADURA2048"
	case KEX_KYBER512:
		return "KEX_KYBER512"
	case KEX_KYBER768:
		return "KEX_KYBER768"
	case KEX_KYBER1024:
		return "KEX_KYBER1024"
	case KEX_NEWHOPE:
		return "KEX_NEWHOPE"
	case KEX_NEWHOPE_SIMPLE:
		return "KEX_NEWHOPE_SIMPLE"
	default:
		return "KEX_ERR_UNK"
	}
}

func (hc *Conn) CAlg() CSCipherAlg {
	return CSCipherAlg(hc.cipheropts & 0x0FF)
}

func (c *CSCipherAlg) String() string {
	switch *c & 0x0FF {
	case CAlgAES256:
		return "C_AES_256"
	case CAlgTwofish128:
		return "C_TWOFISH_128"
	case CAlgBlowfish64:
		return "C_BLOWFISH_64"
	case CAlgCryptMT1:
		return "C_CRYPTMT1"
	case CAlgWanderer:
		return "C_WANDERER"
	default:
		return "C_ERR_UNK"
	}
}

func (hc *Conn) HAlg() CSHmacAlg {
	return CSHmacAlg((hc.cipheropts >> 8) & 0x0FF)
}

func (h *CSHmacAlg) String() string {
	switch (*h >> 8) & 0x0FF {
	case HmacSHA256:
		return "H_SHA256"
	case HmacSHA512:
		return "C_SHA512"
	default:
		return "H_ERR_UNK"
	}
}

func _initLogging(d bool, c string, f logger.Priority) {
	if Log == nil {
		Log, _ = logger.New(f, fmt.Sprintf("%s:xsnet", c))
	}
	if d {
		log.SetFlags(0) // syslog will have date,time
		log.SetOutput(Log)
	} else {
		log.SetOutput(ioutil.Discard)
	}
}

func Init(d bool, c string, f logger.Priority) {
	_initLogging(d, c, f)
}

func (hc *Conn) Lock() {
	hc.m.Lock()
}

func (hc *Conn) Unlock() {
	hc.m.Unlock()
}

func (hc Conn) KEX() KEXAlg {
	return hc.kex
}

func (hc Conn) GetStatus() CSOType {
	return *hc.closeStat
}

func (hc *Conn) SetStatus(stat CSOType) {
	*hc.closeStat = stat
	log.Println("closeStat:", *hc.closeStat)
}

// ConnOpts returns the cipher/hmac options value, which is sent to the
// peer but is not itself part of the KEx.
//
// (Used for protocol-level negotiations after KEx such as
// cipher/HMAC algorithm options etc.)
func (hc Conn) ConnOpts() uint32 {
	return hc.cipheropts
}

// SetConnOpts sets the cipher/hmac options value, which is sent to the
// peer as part of KEx but not part of the KEx itself.
//
// opts - bitfields for cipher and hmac alg. to use after KEx
func (hc *Conn) SetConnOpts(copts uint32) {
	hc.cipheropts = copts
}

// Opts returns the protocol options value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this for protocol-level options not part
// of the KEx or encryption info used by the connection.
func (hc Conn) Opts() uint32 {
	return hc.opts
}

// SetOpts sets the protocol options value, which is sent to the peer
// but is not itself part of the KEx or connection (cipher/hmac) setup.
//
// Consumers of this lib may use this for protocol-level options not part
// of the KEx of encryption info used by the connection.
//
// opts - a uint32, caller-defined
func (hc *Conn) SetOpts(opts uint32) {
	hc.opts = opts
}

// Return a new xsnet.Conn
//
// Note this is internal: use Dial() or Accept()
func _new(kexAlg KEXAlg, conn *net.Conn) (hc *Conn, e error) {
	// Set up stuff common to all KEx/KEM types
	hc = &Conn{kex: kexAlg,
		m:         &sync.Mutex{},
		c:         conn,
		closeStat: new(CSOType),
		WinCh:     make(chan WinSize, 1),
		dBuf:      new(bytes.Buffer)}
	tempMap := make(map[uint16]*TunEndpoint)
	hc.tuns = &tempMap

	*hc.closeStat = CSEStillOpen // open or prematurely-closed status

	// Set up KEx/KEM-specifics
	switch kexAlg {
	case KEX_HERRADURA256:
		fallthrough
	case KEX_HERRADURA512:
		fallthrough
	case KEX_HERRADURA1024:
		fallthrough
	case KEX_HERRADURA2048:
		fallthrough
	case KEX_KYBER512:
		fallthrough
	case KEX_KYBER768:
		fallthrough
	case KEX_KYBER1024:
		fallthrough
	case KEX_NEWHOPE:
		fallthrough
	case KEX_NEWHOPE_SIMPLE:
		log.Printf("[KEx alg %d accepted]\n", kexAlg)
	default:
		// UNREACHABLE: _getkexalgnum() guarantees a valid KEX value
		hc.kex = KEX_HERRADURA512
		log.Printf("[KEx alg %d ?? defaults to %d]\n", kexAlg, hc.kex)
	}
	return
}

// applyConnExtensions processes optional Dial() negotiation
// parameters. See also getkexalgnum().
//
// Currently defined extension values
//
// KEx algs
//
// KEX_HERRADURA256 KEX_HERRADURA512 KEX_HERRADURA1024 KEX_HERRADURA2048
//
// KEX_KYBER512 KEX_KYBER768 KEX_KYBER1024
//
// KEX_NEWHOPE KEX_NEWHOPE_SIMPLE
//
// Session (symmetric) crypto
//
// C_AES_256 C_TWOFISH_128 C_BLOWFISH_128 C_CRYPTMT1
//
// Session HMACs
//
// H_SHA256 H_SHA512
func (hc *Conn) applyConnExtensions(extensions ...string) {
	for _, s := range extensions {
		switch s {
		case "C_AES_256":
			log.Println("[extension arg = C_AES_256]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgAES256
		case "C_TWOFISH_128":
			log.Println("[extension arg = C_TWOFISH_128]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgTwofish128
		case "C_BLOWFISH_64":
			log.Println("[extension arg = C_BLOWFISH_64]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgBlowfish64
		case "C_CRYPTMT1":
			log.Println("[extension arg = C_CRYPTMT1]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgCryptMT1
		case "C_WANDERER":
			log.Println("[extension arg = C_WANDERER]")
			hc.cipheropts &= (0xFFFFFF00)
			hc.cipheropts |= CAlgWanderer
		case "H_SHA256":
			log.Println("[extension arg = H_SHA256]")
			hc.cipheropts &= (0xFFFF00FF)
			hc.cipheropts |= (HmacSHA256 << 8)
		case "H_SHA512":
			log.Println("[extension arg = H_SHA512]")
			hc.cipheropts &= (0xFFFF00FF)
			hc.cipheropts |= (HmacSHA512 << 8)
			//default:
			//	log.Printf("[Dial ext \"%s\" ignored]\n", s)
		}
	}
}

func getkexalgnum(extensions ...string) (k KEXAlg) {
	k = KEX_HERRADURA512 // default
	for _, s := range extensions {
		switch s {
		case "KEX_HERRADURA256":
			k = KEX_HERRADURA256
			break //out of for
		case "KEX_HERRADURA512":
			k = KEX_HERRADURA512
			break //out of for
		case "KEX_HERRADURA1024":
			k = KEX_HERRADURA1024
			break //out of for
		case "KEX_HERRADURA2048":
			k = KEX_HERRADURA2048
			break //out of for
		case "KEX_KYBER512":
			k = KEX_KYBER512
			break //out of for
		case "KEX_KYBER768":
			k = KEX_KYBER768
			break //out of for
		case "KEX_KYBER1024":
			k = KEX_KYBER1024
			break //out of for
		case "KEX_NEWHOPE":
			k = KEX_NEWHOPE
			break //out of for
		case "KEX_NEWHOPE_SIMPLE":
			k = KEX_NEWHOPE_SIMPLE
			break //out of for
		}
	}
	return
}

// randReader wraps rand.Read() in a struct that implements io.Reader
// for use by the Kyber and NEWHOPE/NEWHOPE_SIMPLE KEM methods.
type randReader struct {
}

func (r randReader) Read(b []byte) (n int, e error) {
	n, e = rand.Read(b)
	return
}

func NewHopeDialSetup(c io.ReadWriter, hc *Conn) (err error) {
	// Send xsnet.Conn parameters to remote side

	// Alice, step 1: Generate a key pair.
	r := new(randReader)
	rand.Seed(time.Now().UnixNano())

	privKeyAlice, pubKeyAlice, err := newhope.GenerateKeyPairAlice(r)
	if err != nil {
		panic(err)
	}

	// Alice, step 2: Send the public key to Bob
	fmt.Fprintf(c, "0x%x\n0x%x:0x%x\n", pubKeyAlice.Send,
		hc.cipheropts, hc.opts)

	// [Bob does step 1-3], from which we read Bob's pubkey
	publicKeyBob := big.NewInt(0)
	fmt.Fscanf(c, "0x%x\n", publicKeyBob)
	var pubKeyBob newhope.PublicKeyBob
	for i := range pubKeyBob.Send {
		pubKeyBob.Send[i] = publicKeyBob.Bytes()[i]
	}
	log.Printf("[Got server pubKey[]:%v]\n", pubKeyBob)

	// Read cipheropts, session opts
	_, err = fmt.Fscanf(c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	if err != nil {
		return err
	}

	// Alice, step 3: Derive shared secret
	// (NOTE: actual over-wire exchange was already done above. This is
	//  the math voodoo 'exchange' done after receiving data from Bob.)
	aliceSharedSecret, err := newhope.KeyExchangeAlice(&pubKeyBob, privKeyAlice)
	if err != nil {
		panic(err)
	}
	log.Printf("[Derived sharedSecret:0x%x]\n", aliceSharedSecret)
	hc.r, hc.rm, err = hc.getStream(aliceSharedSecret)
	hc.w, hc.wm, err = hc.getStream(aliceSharedSecret)
	return
}

func NewHopeSimpleDialSetup(c io.ReadWriter, hc *Conn) (err error) {
	// Send xsnet.Conn parameters to remote side

	// Alice, step 1: Generate a key pair.
	r := new(randReader)
	rand.Seed(time.Now().UnixNano())
	privKeyAlice, pubKeyAlice, err := newhope.GenerateKeyPairSimpleAlice(r)
	if err != nil {
		panic(err)
	}

	// Alice, step 2: Send the public key to Bob
	fmt.Fprintf(c, "0x%x\n0x%x:0x%x\n", pubKeyAlice.Send,
		hc.cipheropts, hc.opts)

	// [Bob does step 1-3], from which we read Bob's pubkey
	publicKeyBob := big.NewInt(0)
	fmt.Fscanf(c, "0x%x\n", publicKeyBob)
	var pubKeyBob newhope.PublicKeySimpleBob
	for i := range pubKeyBob.Send {
		pubKeyBob.Send[i] = publicKeyBob.Bytes()[i]
	}
	log.Printf("[Got server pubKey[]:%v]\n", pubKeyBob)

	// Read cipheropts, session opts
	_, err = fmt.Fscanf(c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	if err != nil {
		return err
	}

	// Alice, step 3: Derive shared secret
	// (NOTE: actual over-wire exchange was already done above. This is
	//  the math voodoo 'exchange' done after receiving data from Bob.)
	aliceSharedSecret, err := newhope.KeyExchangeSimpleAlice(&pubKeyBob, privKeyAlice)
	if err != nil {
		panic(err)
	}
	log.Printf("[Derived sharedSecret:0x%x]\n", aliceSharedSecret)
	hc.r, hc.rm, err = hc.getStream(aliceSharedSecret)
	hc.w, hc.wm, err = hc.getStream(aliceSharedSecret)
	return
}

func KyberDialSetup(c io.ReadWriter /*net.Conn*/, hc *Conn) (err error) {
	// Send xsnet.Conn parameters to remote side

	// Alice, step 1: Generate a key pair.
	r := new(randReader)
	rand.Seed(time.Now().UnixNano())
	var alicePublicKey *kyber.PublicKey
	var alicePrivateKey *kyber.PrivateKey
	switch hc.kex {
	case KEX_KYBER512:
		alicePublicKey, alicePrivateKey, err = kyber.Kyber512.GenerateKeyPair(r)
	case KEX_KYBER768:
		alicePublicKey, alicePrivateKey, err = kyber.Kyber768.GenerateKeyPair(r)
	case KEX_KYBER1024:
		alicePublicKey, alicePrivateKey, err = kyber.Kyber1024.GenerateKeyPair(r)
	default:
		alicePublicKey, alicePrivateKey, err = kyber.Kyber768.GenerateKeyPair(r)
	}

	if err != nil {
		panic(err)
	}

	// Alice, step 2: Send the public key to Bob
	fmt.Fprintf(c, "0x%x\n0x%x:0x%x\n", alicePublicKey.Bytes(),
		hc.cipheropts, hc.opts)

	// [Bob, step 1-3], from which we read cipher text
	pubKeyB := make([]byte, 4096)
	fmt.Fscanf(c, "0x%x\n", &pubKeyB)
	//if err != nil {
	//	return err
	//}
	log.Printf("[Got server pubKeyB[]:%v]\n", pubKeyB)

	// Read cipheropts, session opts
	_, err = fmt.Fscanf(c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	if err != nil {
		return err
	}

	// Alice, step 3: Decrypt the KEM cipher text.
	aliceSharedSecret := alicePrivateKey.KEMDecrypt(pubKeyB)

	log.Printf("[Derived sharedSecret:0x%x]\n", aliceSharedSecret)
	hc.r, hc.rm, err = hc.getStream(aliceSharedSecret)
	hc.w, hc.wm, err = hc.getStream(aliceSharedSecret)
	return
}

func HKExDialSetup(c io.ReadWriter /*net.Conn*/, hc *Conn) (err error) {
	var h *hkex.HerraduraKEx
	switch hc.kex {
	case KEX_HERRADURA256:
		h = hkex.New(256, 64)
	case KEX_HERRADURA512:
		h = hkex.New(512, 128)
	case KEX_HERRADURA1024:
		h = hkex.New(1024, 256)
	case KEX_HERRADURA2048:
		h = hkex.New(2048, 512)
	default:
		h = hkex.New(256, 64)
	}

	// Send xsnet.Conn parameters to remote side
	// d is value for Herradura key exchange
	fmt.Fprintf(c, "0x%s\n0x%x:0x%x\n", h.D().Text(16),
		hc.cipheropts, hc.opts)

	// Read peer D over net.Conn (c)
	d := big.NewInt(0)
	_, err = fmt.Fscanln(c, d)
	if err != nil {
		return err
	}
	_, err = fmt.Fscanf(c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	if err != nil {
		return err
	}

	h.SetPeerD(d)
	log.Printf("** local D:%s\n", h.D().Text(16))
	log.Printf("**(c)** peer D:%s\n", h.PeerD().Text(16))
	h.ComputeFA()
	log.Printf("**(c)** FA:%s\n", h.FA())

	hc.r, hc.rm, err = hc.getStream(h.FA().Bytes())
	hc.w, hc.wm, err = hc.getStream(h.FA().Bytes())
	return
}

func NewHopeAcceptSetup(c *net.Conn, hc *Conn) (err error) {
	r := new(randReader)
	rand.Seed(time.Now().UnixNano())
	// Bob, step 1: Deserialize Alice's public key from the binary encoding.
	alicePublicKey := big.NewInt(0)
	_, err = fmt.Fscanln(*c, alicePublicKey)
	log.Printf("[Got client pubKey:0x%x\n]", alicePublicKey)
	if err != nil {
		return err
	}

	var pubKeyAlice newhope.PublicKeyAlice
	for i := range pubKeyAlice.Send {
		pubKeyAlice.Send[i] = alicePublicKey.Bytes()[i]
	}

	_, err = fmt.Fscanf(*c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	log.Printf("[Got cipheropts, opts:%v, %v]", hc.cipheropts, hc.opts)
	if err != nil {
		return err
	}

	// Bob, step 2: Generate the KEM cipher text and shared secret.
	pubKeyBob, bobSharedSecret, err := newhope.KeyExchangeBob(r, &pubKeyAlice)
	if err != nil {
		panic(err)
	}

	// Bob, step 3: Send the cipher text to Alice.
	fmt.Fprintf(*c, "0x%x\n0x%x:0x%x\n", pubKeyBob.Send,
		hc.cipheropts, hc.opts)

	log.Printf("[Derived sharedSecret:0x%x]\n", bobSharedSecret)
	hc.r, hc.rm, err = hc.getStream(bobSharedSecret)
	hc.w, hc.wm, err = hc.getStream(bobSharedSecret)
	return
}

func NewHopeSimpleAcceptSetup(c *net.Conn, hc *Conn) (err error) {
	r := new(randReader)
	rand.Seed(time.Now().UnixNano())
	// Bob, step 1: Deserialize Alice's public key from the binary encoding.
	alicePublicKey := big.NewInt(0)
	_, err = fmt.Fscanln(*c, alicePublicKey)
	log.Printf("[Got client pubKey:0x%x\n]", alicePublicKey)
	if err != nil {
		return err
	}

	var pubKeyAlice newhope.PublicKeySimpleAlice
	for i := range pubKeyAlice.Send {
		pubKeyAlice.Send[i] = alicePublicKey.Bytes()[i]
	}

	_, err = fmt.Fscanf(*c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	log.Printf("[Got cipheropts, opts:%v, %v]", hc.cipheropts, hc.opts)
	if err != nil {
		return err
	}

	// Bob, step 2: Generate the KEM cipher text and shared secret.
	pubKeyBob, bobSharedSecret, err := newhope.KeyExchangeSimpleBob(r, &pubKeyAlice)
	if err != nil {
		panic(err)
	}

	// Bob, step 3: Send the cipher text to Alice.
	fmt.Fprintf(*c, "0x%x\n0x%x:0x%x\n", pubKeyBob.Send,
		hc.cipheropts, hc.opts)

	log.Printf("[Derived sharedSecret:0x%x]\n", bobSharedSecret)
	hc.r, hc.rm, err = hc.getStream(bobSharedSecret)
	hc.w, hc.wm, err = hc.getStream(bobSharedSecret)
	return
}

func KyberAcceptSetup(c *net.Conn, hc *Conn) (err error) {
	// Bob, step 1: Deserialize Alice's public key from the binary encoding.
	alicePublicKey := big.NewInt(0)
	_, err = fmt.Fscanln(*c, alicePublicKey)
	log.Printf("[Got client pubKey:0x%x\n]", alicePublicKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fscanf(*c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	log.Printf("[Got cipheropts, opts:%v, %v]", hc.cipheropts, hc.opts)
	if err != nil {
		return err
	}

	var peerPublicKey *kyber.PublicKey
	switch hc.kex {
	case KEX_KYBER512:
		peerPublicKey, err = kyber.Kyber512.PublicKeyFromBytes(alicePublicKey.Bytes())
	case KEX_KYBER768:
		peerPublicKey, err = kyber.Kyber768.PublicKeyFromBytes(alicePublicKey.Bytes())
	case KEX_KYBER1024:
		peerPublicKey, err = kyber.Kyber1024.PublicKeyFromBytes(alicePublicKey.Bytes())
	default:
		peerPublicKey, err = kyber.Kyber768.PublicKeyFromBytes(alicePublicKey.Bytes())
	}

	if err != nil {
		panic(err)
	}

	// Bob, step 2: Generate the KEM cipher text and shared secret.
	r := new(randReader)
	rand.Seed(time.Now().UnixNano())
	cipherText, bobSharedSecret, err := peerPublicKey.KEMEncrypt(r)
	if err != nil {
		panic(err)
	}

	// Bob, step 3: Send the cipher text to Alice.
	fmt.Fprintf(*c, "0x%x\n0x%x:0x%x\n", cipherText,
		hc.cipheropts, hc.opts)

	log.Printf("[Derived sharedSecret:0x%x]\n", bobSharedSecret)
	hc.r, hc.rm, err = hc.getStream(bobSharedSecret)
	hc.w, hc.wm, err = hc.getStream(bobSharedSecret)
	return
}

func HKExAcceptSetup(c *net.Conn, hc *Conn) (err error) {
	var h *hkex.HerraduraKEx
	switch hc.kex {
	case KEX_HERRADURA256:
		h = hkex.New(256, 64)
	case KEX_HERRADURA512:
		h = hkex.New(512, 128)
	case KEX_HERRADURA1024:
		h = hkex.New(1024, 256)
	case KEX_HERRADURA2048:
		h = hkex.New(2048, 512)
	default:
		h = hkex.New(256, 64)
	}

	// Read in xsnet.Conn parameters over raw Conn c
	// d is value for Herradura key exchange
	d := big.NewInt(0)
	_, err = fmt.Fscanln(*c, d)
	log.Printf("[Got d:%v]", d)
	if err != nil {
		return err
	}
	_, err = fmt.Fscanf(*c, "0x%x:0x%x\n",
		&hc.cipheropts, &hc.opts)
	log.Printf("[Got cipheropts, opts:%v, %v]", hc.cipheropts, hc.opts)
	if err != nil {
		return err
	}
	h.SetPeerD(d)
	log.Printf("** D:%s\n", h.D().Text(16))
	log.Printf("**(s)** peerD:%s\n", h.PeerD().Text(16))
	h.ComputeFA()
	log.Printf("**(s)** FA:%s\n", h.FA())

	// Send D and cipheropts/conn_opts to peer
	fmt.Fprintf(*c, "0x%s\n0x%x:0x%x\n", h.D().Text(16),
		hc.cipheropts, hc.opts)

	hc.r, hc.rm, err = hc.getStream(h.FA().Bytes())
	hc.w, hc.wm, err = hc.getStream(h.FA().Bytes())
	return
}

// Dial as net.Dial(), but with implicit key exchange to set up secure
// channel on connect
//
//   Can be called like net.Dial(), defaulting to C_AES_256/H_SHA256,
//   or additional extensions can be passed amongst the following:
//
//   "C_AES_256" | "C_TWOFISH_128" | ...
//
//   "H_SHA256" | "H_SHA512" | ...
//
// See go doc -u xsnet.applyConnExtensions
func Dial(protocol string, ipport string, extensions ...string) (hc Conn, err error) {
	if Log == nil {
		Init(false, "client", logger.LOG_DAEMON|logger.LOG_DEBUG)
	}

	var c net.Conn
	if protocol == "kcp" {
		c, err = kcpDial(ipport, extensions)
		if err != nil {
			return Conn{}, err
		}
	} else {
		// Open raw Conn c
		c, err = net.Dial(protocol, ipport)
		if err != nil {
			return Conn{}, err
		}
	}
	// Init xsnet.Conn hc over net.Conn c
	ret, err := _new(getkexalgnum(extensions...), &c)
	if err != nil {
		return Conn{}, err
	}
	hc = *ret

	// Client has full control over Conn extensions. It's the server's
	// responsibility to accept or reject the proposed parameters.
	hc.applyConnExtensions(extensions...)

	// Perform Key Exchange according to client-request algorithm
	fmt.Fprintf(c, "%02x\n", hc.kex)
	switch hc.kex {
	case KEX_HERRADURA256:
		fallthrough
	case KEX_HERRADURA512:
		fallthrough
	case KEX_HERRADURA1024:
		fallthrough
	case KEX_HERRADURA2048:
		log.Printf("[Setting up for KEX_HERRADURA %d]\n", hc.kex)
		if HKExDialSetup(c, &hc) != nil {
			return Conn{}, nil
		}
	case KEX_KYBER512:
		fallthrough
	case KEX_KYBER768:
		fallthrough
	case KEX_KYBER1024:
		log.Printf("[Setting up for KEX_KYBER %d]\n", hc.kex)
		if KyberDialSetup(c, &hc) != nil {
			return Conn{}, nil
		}
	case KEX_NEWHOPE:
		log.Printf("[Setting up for KEX_NEWHOPE %d]\n", hc.kex)
		if NewHopeDialSetup(c, &hc) != nil {
			return Conn{}, nil
		}
	case KEX_NEWHOPE_SIMPLE:
		log.Printf("[Setting up for KEX_NEWHOPE_SIMPLE %d]\n", hc.kex)
		if NewHopeSimpleDialSetup(c, &hc) != nil {
			return Conn{}, nil
		}
	default:
		return Conn{}, err
	}
	return
}

// Close a hkex.Conn
func (hc *Conn) Close() (err error) {
	hc.DisableChaff()
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, uint32(*hc.closeStat))
	log.Printf("** Writing closeStat %d at Close()\n", *hc.closeStat)
	//(*hc.c).SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	hc.WritePacket(s, CSOExitStatus)
	err = (*hc.c).Close()
	logger.LogDebug(fmt.Sprintln("[Conn Closing]"))
	return
}

// LocalAddr returns the local network address.
func (hc *Conn) LocalAddr() net.Addr {
	return (*hc.c).LocalAddr()
}

// RemoteAddr returns the remote network address.
func (hc *Conn) RemoteAddr() net.Addr {
	return (*hc.c).RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (hc *Conn) SetDeadline(t time.Time) error {
	return (*hc.c).SetDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (hc *Conn) SetWriteDeadline(t time.Time) error {
	return (*hc.c).SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (hc *Conn) SetReadDeadline(t time.Time) error {
	return (*hc.c).SetReadDeadline(t)
}

/*---------------------------------------------------------------------*/

// HKExListener is a Listener conforming to net.Listener
//
// See go doc net.Listener
type HKExListener struct {
	l     net.Listener
	proto string
}

// Listen for a connection
//
// See go doc net.Listen
func Listen(proto string, ipport string, extensions ...string) (hl HKExListener, e error) {
	if Log == nil {
		Init(false, "server", logger.LOG_DAEMON|logger.LOG_DEBUG)
	}

	var lErr error
	var l net.Listener

	if proto == "kcp" {
		l, lErr = kcpListen(ipport, extensions)
	} else {
		l, lErr = net.Listen(proto, ipport)
	}
	if lErr != nil {
		return HKExListener{nil, proto}, lErr
	}
	logger.LogDebug(fmt.Sprintf("[Listening (proto '%s') on %s]\n", proto, ipport))
	hl.l = l
	hl.proto = proto
	return
}

// Close a hkex Listener - closes the Listener.
// Any blocked Accept operations will be unblocked and return errors.
//
// See go doc net.Listener.Close
func (hl HKExListener) Close() error {
	logger.LogDebug(fmt.Sprintln("[Listener Closed]"))
	return hl.l.Close()
}

// Addr returns a the listener's network address.
//
// See go doc net.Listener.Addr
func (hl HKExListener) Addr() net.Addr {
	return hl.l.Addr()
}

// Accept a client connection, conforming to net.Listener.Accept()
//
// See go doc net.Listener.Accept
func (hl *HKExListener) Accept() (hc Conn, err error) {
	var c net.Conn
	if hl.proto == "kcp" {
		c, err = hl.AcceptKCP()
		if err != nil {
			return Conn{}, err
		}
		logger.LogDebug(fmt.Sprintln("[kcp.Listener Accepted]"))
	} else {
		// Open raw Conn c
		c, err = hl.l.Accept()
		if err != nil {
			return Conn{}, err
		}

		logger.LogDebug(fmt.Sprintln("[net.Listener Accepted]"))
	}
	// Read KEx alg proposed by client
	var kexAlg KEXAlg
	//! NB. Was using fmt.FScanln() here, but integers with a leading zero
	//  were being mis-scanned? (is it an octal thing? Investigate.)
	_, err = fmt.Fscanf(c, "%02x\n", &kexAlg)
	if err != nil {
		return Conn{}, err
	}
	log.Printf("[Client proposed KEx alg: %v]\n", kexAlg)
	// --

	ret, err := _new(kexAlg, &c)
	if err != nil {
		return Conn{}, err
	}
	hc = *ret

	switch hc.kex {
	case KEX_HERRADURA256:
		fallthrough
	case KEX_HERRADURA512:
		fallthrough
	case KEX_HERRADURA1024:
		fallthrough
	case KEX_HERRADURA2048:
		log.Printf("[Setting up for KEX_HERRADURA %d]\n", hc.kex)
		if HKExAcceptSetup(&c, &hc) != nil {
			return Conn{}, err
		}
	case KEX_KYBER512:
		fallthrough
	case KEX_KYBER768:
		fallthrough
	case KEX_KYBER1024:
		log.Printf("[Setting up for KEX_KYBER %d]\n", hc.kex)
		if KyberAcceptSetup(&c, &hc) != nil {
			return Conn{}, err
		}
	case KEX_NEWHOPE:
		log.Printf("[Setting up for KEX_NEWHOPE %d]\n", hc.kex)
		if NewHopeAcceptSetup(&c, &hc) != nil {
			return Conn{}, err
		}
	case KEX_NEWHOPE_SIMPLE:
		log.Printf("[Setting up for KEX_NEWHOPE_SIMPLE %d]\n", hc.kex)
		if NewHopeSimpleAcceptSetup(&c, &hc) != nil {
			return Conn{}, err
		}
	default:
		return Conn{}, err
	}

	// Finally, ensure alg proposed by client is allowed by server config
	//if hc.kex.String() {
	log.Println("[hc.Accept successful]")
	return
}

/*---------------------------------------------------------------------*/

// Read into a byte slice
//
// In addition to regular io.Reader behaviour this does demultiplexing of
// secured terminal comms and (if defined) tunnel traffic and session control
// packet processing.
//
// See go doc io.Reader
func (hc Conn) Read(b []byte) (n int, err error) {
	for {
		if hc.dBuf.Len() > 0 {
			break
		}

		var ctrlStatOp uint8
		var hmacIn [HMAC_CHK_SZ]uint8
		var payloadLen uint32

		// Read ctrl/status opcode (CSOHmacInvalid on hmac mismatch)
		err = binary.Read(*hc.c, binary.BigEndian, &ctrlStatOp)
		if err != nil {
			if err.Error() == "EOF" {
				return 0, io.EOF
			}
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				logger.LogDebug(fmt.Sprintln("[Client hung up]"))
				return 0, io.EOF
			}
			etxt := fmt.Sprintf("** Failed read:%s (%s) **", "ctrlStatOp", err)
			logger.LogDebug(etxt)
			return 0, errors.New(etxt)
		}
		log.Printf("[ctrlStatOp: %v]\n", ctrlStatOp)
		if ctrlStatOp == CSOHmacInvalid {
			// Other side indicated channel tampering, close channel
			hc.Close()
			return 0, errors.New("** ALERT - remote end detected HMAC mismatch - possible channel tampering **")
		}

		// Read the hmac and payload len first
		err = binary.Read(*hc.c, binary.BigEndian, &hmacIn)
		if err != nil {
			if err.Error() == "EOF" {
				return 0, io.EOF
			}
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				logger.LogDebug(fmt.Sprintln("[Client hung up]"))
				return 0, io.EOF
			}
			etxt := fmt.Sprintf("** Failed read:%s (%s) **", "HMAC", err)
			logger.LogDebug(etxt)
			return 0, errors.New(etxt)
		}

		err = binary.Read(*hc.c, binary.BigEndian, &payloadLen)
		if err != nil {
			if err.Error() == "EOF" {
				return 0, io.EOF
			}
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				logger.LogDebug(fmt.Sprintln("[Client hung up]"))
				return 0, io.EOF
			}
			etxt := fmt.Sprintf("** Failed read:%s (%s) **", "payloadLen", err)
			logger.LogDebug(etxt)
			return 0, errors.New(etxt)
		}

		if payloadLen > MAX_PAYLOAD_LEN {
			logger.LogDebug(fmt.Sprintf("[Insane payloadLen:%v]\n", payloadLen))
			hc.Close()
			return 1, errors.New("Insane payloadLen")
		}

		var payloadBytes = make([]byte, payloadLen)
		n, err = io.ReadFull(*hc.c, payloadBytes)
		if err != nil {
			if err.Error() == "EOF" {
				return 0, io.EOF
			}
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				logger.LogDebug(fmt.Sprintln("[Client hung up]"))
				return 0, io.EOF
			}
			etxt := fmt.Sprintf("** Failed read:%s (%s) **", "payloadBytes", err)
			logger.LogDebug(etxt)
			return 0, errors.New(etxt)
		}

		if hc.logCipherText {
			log.Printf("  <:ctext:\r\n%s\r\n", hex.Dump(payloadBytes[:n]))
		}

		db := bytes.NewBuffer(payloadBytes[:n]) //copying payloadBytes to db
		// The StreamReader acts like a pipe, decrypting
		// whatever is available and forwarding the result
		// to the parameter of Read() as a normal io.Reader
		rs := &cipher.StreamReader{S: hc.r, R: db}
		// The caller isn't necessarily reading the full payload so we need
		// to decrypt to an intermediate buffer, draining it on demand of caller
		decryptN, err := rs.Read(payloadBytes)
		if hc.logPlainText {
			log.Printf("  <-ptext:\r\n%s\r\n", hex.Dump(payloadBytes[:n]))
		}
		if err != nil {
			log.Println("xsnet.Read():", err)
			//panic(err)
		} else {
			hc.rm.Write(payloadBytes) // Calc hmac on received data
			// Padding: Read padSide, padLen, (padding | d) or (d | padding)
			padSide := payloadBytes[0]
			padLen := payloadBytes[1]

			payloadBytes = payloadBytes[2:]
			if padSide == 0 {
				payloadBytes = payloadBytes[padLen:]
			} else {
				payloadBytes = payloadBytes[0 : len(payloadBytes)-int(padLen)]
			}

			//fmt.Printf("padSide:%d padLen:%d payloadBytes:%s\n",
			//	padSide, padLen, hex.Dump(payloadBytes))

			// Throw away pkt if it's chaff (ie., caller to Read() won't see this data)
			if ctrlStatOp == CSOChaff {
				log.Printf("[Chaff pkt, discarded (len %d)]\n", decryptN)
			} else if ctrlStatOp == CSOTermSize {
				fmt.Sscanf(string(payloadBytes), "%d %d", &hc.Rows, &hc.Cols)
				log.Printf("[TermSize pkt: rows %v cols %v]\n", hc.Rows, hc.Cols)
				hc.WinCh <- WinSize{hc.Rows, hc.Cols}
			} else if ctrlStatOp == CSOExitStatus {
				if len(payloadBytes) > 0 {
					hc.SetStatus(CSOType(binary.BigEndian.Uint32(payloadBytes)))
				} else {
					logger.LogDebug(fmt.Sprintln("[truncated payload, cannot determine CSOExitStatus]"))
					hc.SetStatus(CSETruncCSO)
				}
				hc.Close()
			} else if ctrlStatOp == CSOTunSetup {
				// server side tunnel setup in response to client
				lport := binary.BigEndian.Uint16(payloadBytes[0:2])
				rport := binary.BigEndian.Uint16(payloadBytes[2:4])
				if _, ok := (*hc.tuns)[rport]; !ok {
					// tunnel first-time open
					logger.LogDebug(fmt.Sprintf("[Server] Got Initial CSOTunSetup [%d:%d]", lport, rport))
					hc.StartServerTunnel(lport, rport)
				} else {
					logger.LogDebug(fmt.Sprintf("[Server] Got CSOTunSetup [%d:%d]", lport, rport))
				}
				(*hc.tuns)[rport].Ctl <- 'd' // Dial() rport
			} else if ctrlStatOp == CSOTunSetupAck {
				lport := binary.BigEndian.Uint16(payloadBytes[0:2])
				rport := binary.BigEndian.Uint16(payloadBytes[2:4])
				if _, ok := (*hc.tuns)[rport]; !ok {
					// tunnel first-time open
					logger.LogDebug(fmt.Sprintf("[Client] Got Initial CSOTunSetupAck [%d:%d]", lport, rport))
					hc.StartClientTunnel(lport, rport)
				} else {
					logger.LogDebug(fmt.Sprintf("[Client] Got CSOTunSetupAck [%d:%d]", lport, rport))
				}
				(*hc.tuns)[rport].Ctl <- 'a' // Listen() for lport connection
			} else if ctrlStatOp == CSOTunRefused {
				// client side receiving CSOTunRefused means the remote side
				// could not dial() rport. So we cannot yet listen()
				// for client-side on lport.
				lport := binary.BigEndian.Uint16(payloadBytes[0:2])
				rport := binary.BigEndian.Uint16(payloadBytes[2:4])
				logger.LogDebug(fmt.Sprintf("[Client] Got CSOTunRefused [%d:%d]", lport, rport))
				if _, ok := (*hc.tuns)[rport]; ok {
					hc.MarkTunDead(rport)
				} else {
					logger.LogDebug(fmt.Sprintf("[Client] CSOTunRefused on already-closed tun [%d:%d]", lport, rport))
				}
			} else if ctrlStatOp == CSOTunDisconn {
				// server side's rport has disconnected (server lost)
				lport := binary.BigEndian.Uint16(payloadBytes[0:2])
				rport := binary.BigEndian.Uint16(payloadBytes[2:4])
				logger.LogDebug(fmt.Sprintf("[Client] Got CSOTunDisconn [%d:%d]", lport, rport))
				if _, ok := (*hc.tuns)[rport]; ok {
					hc.MarkTunDead(rport)
				} else {
					logger.LogDebug(fmt.Sprintf("[Client] CSOTunDisconn on already-closed tun [%d:%d]", lport, rport))
				}
			} else if ctrlStatOp == CSOTunHangup {
				// client side's lport has hung up
				lport := binary.BigEndian.Uint16(payloadBytes[0:2])
				rport := binary.BigEndian.Uint16(payloadBytes[2:4])
				logger.LogDebug(fmt.Sprintf("[Server] Got CSOTunHangup [%d:%d]", lport, rport))
				if _, ok := (*hc.tuns)[rport]; ok {
					hc.MarkTunDead(rport)
				} else {
					logger.LogDebug(fmt.Sprintf("[Server] CSOTunHangup to already-closed tun [%d:%d]", lport, rport))
				}
			} else if ctrlStatOp == CSOTunData {
				lport := binary.BigEndian.Uint16(payloadBytes[0:2])
				rport := binary.BigEndian.Uint16(payloadBytes[2:4])
				//fmt.Printf("[Got CSOTunData: [lport %d:rport %d] data:%v\n", lport, rport, payloadBytes[4:])
				if _, ok := (*hc.tuns)[rport]; ok {
					if hc.logTunActivity {
						logger.LogDebug(fmt.Sprintf("[Writing data to rport [%d:%d]", lport, rport))
					}
					(*hc.tuns)[rport].Data <- payloadBytes[4:]
					hc.ResetTunnelAge(rport)
				} else {
					logger.LogDebug(fmt.Sprintf("[Attempt to write data to closed tun [%d:%d]", lport, rport))
				}
			} else if ctrlStatOp == CSOTunKeepAlive {
				// client side has sent keepalive for tunnels -- if client
				// dies or exits unexpectedly the absence of this will
				// let the server know to hang up on Dial()ed server rports.
				_ = binary.BigEndian.Uint16(payloadBytes[0:2])
				//logger.LogDebug(fmt.Sprintf("[Server] Got CSOTunKeepAlive"))
				for _, t := range *hc.tuns {
					hc.Lock()
					t.KeepAlive = 0
					hc.Unlock()
				}
			} else if ctrlStatOp == CSONone {
				hc.dBuf.Write(payloadBytes)
			} else {
				logger.LogDebug(fmt.Sprintf("[Unknown CSOType:%d]", ctrlStatOp))
			}

			hTmp := hc.rm.Sum(nil)[0:HMAC_CHK_SZ]
			log.Printf("<%04x) HMAC:(i)%s (c)%02x\r\n", decryptN, hex.EncodeToString([]byte(hmacIn[0:])), hTmp)

			if *hc.closeStat == CSETruncCSO {
				logger.LogDebug(fmt.Sprintln("[cannot verify HMAC]"))
			} else {
				// Log alert if hmac didn't match, corrupted channel
				if !bytes.Equal(hTmp, []byte(hmacIn[0:])) /*|| hmacIn[0] > 0xf8*/ {
					logger.LogDebug(fmt.Sprintln("** ALERT - detected HMAC mismatch, possible channel tampering **"))
					_, _ = (*hc.c).Write([]byte{CSOHmacInvalid})
				}
			}
		}
	}

	retN := hc.dBuf.Len()
	if retN > len(b) {
		retN = len(b)
	}

	log.Printf("Read() got %d bytes\n", retN)
	copy(b, hc.dBuf.Next(retN))
	return retN, nil
}

// Write a byte slice
//
// See go doc io.Writer
func (hc Conn) Write(b []byte) (n int, err error) {
	//fmt.Printf("WRITE(%d)\n", len(b))
	n, err = hc.WritePacket(b, CSONone)
	//fmt.Printf("WROTE(%d)\n", n)
	return n, err
}

// Write a byte slice with specified ctrlStatOp byte
func (hc *Conn) WritePacket(b []byte, ctrlStatOp byte) (n int, err error) {
	//log.Printf("[Encrypting...]\r\n")
	var hmacOut []uint8
	var payloadLen uint32

	if hc.m == nil || hc.wm == nil {
		return 0, errors.New("Secure chan not ready for writing")
	}

	//Padding prior to encryption
	padSz := (rand.Intn(PAD_SZ) / 2) + (PAD_SZ / 2)
	padLen := padSz - ((len(b) + padSz) % padSz)
	if padLen == padSz {
		// No padding required
		padLen = 0
	}
	padBytes := make([]byte, padLen)
	rand.Read(padBytes)
	// For a little more confusion let's support padding either before
	// or after the payload.
	padSide := rand.Intn(2)
	//fmt.Printf("--\n")
	//fmt.Printf("PRE_PADDING:%s\r\n", hex.Dump(b))
	//fmt.Printf("padSide:%d padLen:%d\r\n", padSide, padLen)
	if padSide == 0 {
		b = append([]byte{byte(padSide)}, append([]byte{byte(padLen)}, append(padBytes, b...)...)...)
	} else {
		b = append([]byte{byte(padSide)}, append([]byte{byte(padLen)}, append(b, padBytes...)...)...)
	}
	//fmt.Printf("POST_PADDING:%s\r\n", hex.Dump(b))
	//fmt.Printf("--\r\n")

	// N.B. Originally this Lock() surrounded only the
	// calls to binary.Write(hc.c ..) however there appears
	// to be some other unshareable state in the Conn
	// struct that must be protected to serialize main and
	// chaff data written to it.
	//
	// Would be nice to determine if the mutex scope
	// could be tightened.
	hc.Lock()
	payloadLen = uint32(len(b))
	//!fmt.Printf("  --== payloadLen:%d\n", payloadLen)
	if hc.logPlainText {
		log.Printf("  :>ptext:\r\n%s\r\n", hex.Dump(b[0:payloadLen]))
	}

	// Calculate hmac on payload
	hc.wm.Write(b[0:payloadLen])
	hmacOut = hc.wm.Sum(nil)[0:HMAC_CHK_SZ]

	//log.Printf("  (%08x> HMAC(o):%s\r\n", payloadLen, hex.EncodeToString(hmacOut))

	var wb bytes.Buffer
	// The StreamWriter acts like a pipe, forwarding whatever is
	// written to it through the cipher, encrypting as it goes
	ws := &cipher.StreamWriter{S: hc.w, W: &wb}
	_, err = ws.Write(b[0:payloadLen])
	if err != nil {
		panic(err)
	}
	if hc.logCipherText {
		log.Printf("  ->ctext:\r\n%s\r\n", hex.Dump(wb.Bytes()))
	}

	err = binary.Write(*hc.c, binary.BigEndian, &ctrlStatOp)
	if err == nil {
		// Write hmac LSB, payloadLen followed by payload
		err = binary.Write(*hc.c, binary.BigEndian, hmacOut)
		if err == nil {
			err = binary.Write(*hc.c, binary.BigEndian, payloadLen)
			if err == nil {
				n, err = (*hc.c).Write(wb.Bytes())
			} else {
				//fmt.Println("[c]WriteError!")
			}
		} else {
			//fmt.Println("[b]WriteError!")
		}
	} else {
		//fmt.Println("[a]WriteError!")
	}
	hc.Unlock()

	if err != nil {
		log.Println(err)
	}

	// We must 'lie' to caller indicating the length of THEIR
	// data written (ie., not including the padding and padding headers)
	return n - 2 - int(padLen), err
}

func (hc *Conn) EnableChaff() {
	hc.chaff.shutdown = false
	hc.chaff.enabled = true
	log.Println("Chaffing ENABLED")
	hc.chaffHelper()
}

func (hc *Conn) DisableChaff() {
	hc.chaff.enabled = false
	log.Println("Chaffing DISABLED")
}

func (hc *Conn) ShutdownChaff() {
	hc.chaff.shutdown = true
	log.Println("Chaffing SHUTDOWN")
}

func (hc *Conn) SetupChaff(msecsMin uint, msecsMax uint, szMax uint) {
	hc.chaff.msecsMin = msecsMin //move these to params of chaffHelper() ?
	hc.chaff.msecsMax = msecsMax
	hc.chaff.szMax = szMax
}

// Helper routine to spawn a chaffing goroutine for each Conn
func (hc *Conn) chaffHelper() {
	go func() {
		for {
			var nextDuration int
			if hc.chaff.enabled {
				var bufTmp []byte
				bufTmp = make([]byte, rand.Intn(int(hc.chaff.szMax)))
				min := int(hc.chaff.msecsMin)
				nextDuration = rand.Intn(int(hc.chaff.msecsMax)-min) + min
				_, _ = rand.Read(bufTmp)
				_, err := hc.WritePacket(bufTmp, CSOChaff)
				if err != nil {
					log.Println("[ *** error - chaffHelper quitting *** ]")
					hc.chaff.enabled = false
					break
				}
			}
			time.Sleep(time.Duration(nextDuration) * time.Millisecond)
			if hc.chaff.shutdown {
				log.Println("*** chaffHelper shutting down")
				break
			}

		}
	}()
}
