package xsnet

// Copyright (c) 2017-2020 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

/* Support functions to set up encryption once an HKEx Conn has been
established with FA exchange and support channel operations
(echo, file-copy, remote-cmd, ...) */

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"

	"blitter.com/go/cryptmt"
	"github.com/aead/chacha20/chacha"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"

	// hash algos must be manually imported thusly:
	// (Would be nice if the golang pkg docs were more clear
	// on this...)
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Expand keymat, if necessary, to a minimum of 2x(blocksize).
// Keymat is used for initial key and the IV, hence the 2x.
// This is occasionally necessary for smaller modes of KEX algorithms
// (eg., KEX_HERRADURA256); perhaps an indication these should be
// avoided in favour of larger modes.
//
// This is used for block ciphers; stream ciphers should do their
// own key expansion.
func expandKeyMat(keymat []byte, blocksize int) []byte {
	if len(keymat) < 2*blocksize {
		halg := crypto.SHA256
		mc := halg.New()
		if !halg.Available() {
			log.Fatal("hash not available!")
		}
		_, _ = mc.Write(keymat)
		var xpand []byte
		xpand = mc.Sum(xpand)
		keymat = append(keymat, xpand...)
		log.Println("[NOTE: keymat short - applying key expansion using SHA256]")
	}
	return keymat
}

/* Support functionality to set up encryption after a channel has
been negotiated via xsnet.go
*/
func (hc *Conn) getStream(keymat []byte) (rc cipher.Stream, mc hash.Hash, err error) {
	var key []byte
	var block cipher.Block
	var iv []byte
	var ivlen int

	copts := hc.cipheropts & 0xFF
	// TODO: each cipher alg case should ensure len(keymat.Bytes())
	// is >= 2*cipher.BlockSize (enough for both key and iv)
	switch copts {
	case CAlgAES256:
		keymat = expandKeyMat(keymat, aes.BlockSize)
		key = keymat[0:aes.BlockSize]
		block, err = aes.NewCipher(key)
		ivlen = aes.BlockSize
		iv = keymat[aes.BlockSize : aes.BlockSize+ivlen]
		rc = cipher.NewOFB(block, iv)
		log.Printf("[cipher AES_256 (%d)]\n", copts)
	case CAlgTwofish128:
		keymat = expandKeyMat(keymat, twofish.BlockSize)
		key = keymat[0:twofish.BlockSize]
		block, err = twofish.NewCipher(key)
		ivlen = twofish.BlockSize
		iv = keymat[twofish.BlockSize : twofish.BlockSize+ivlen]
		rc = cipher.NewOFB(block, iv)
		log.Printf("[cipher TWOFISH_128 (%d)]\n", copts)
	case CAlgBlowfish64:
		keymat = expandKeyMat(keymat, blowfish.BlockSize)
		key = keymat[0:blowfish.BlockSize]
		block, err = blowfish.NewCipher(key)
		ivlen = blowfish.BlockSize
		// N.b. Bounds enforcement of differing cipher algorithms
		// ------------------------------------------------------
		// cipher/aes and x/cipher/twofish appear to allow one to
		// pass an iv larger than the blockSize harmlessly to
		// cipher.NewOFB(); x/cipher/blowfish implementation will
		// segfault here if len(iv) is not exactly blowfish.BlockSize.
		//
		// I assume the other two check bounds and only
		// copy what's needed whereas blowfish does no such check.
		iv = keymat[blowfish.BlockSize : blowfish.BlockSize+ivlen]
		rc = cipher.NewOFB(block, iv)
		log.Printf("[cipher BLOWFISH_64 (%d)]\n", copts)
	case CAlgCryptMT1:
		rc = cryptmt.New(nil, nil, keymat)
		log.Printf("[cipher CRYPTMT1 (%d)]\n", copts)
	case CAlgChaCha20_12:
		keymat = expandKeyMat(keymat, chacha.KeySize)
		key = keymat[0:chacha.KeySize]
		ivlen = chacha.INonceSize
		iv = keymat[chacha.KeySize : chacha.KeySize+ivlen]
		rc, err = chacha.NewCipher(iv, key, 20)
		if err != nil {
			log.Printf("[ChaCha20 config error]\n")
			fmt.Printf("[ChaCha20 config error]\n")
		}
		// TODO: SetCounter() to something derived from key or nonce or extra keymat?
		log.Printf("[cipher CHACHA20_12 (%d)]\n", copts)
	default:
		log.Printf("[invalid cipher (%d)]\n", copts)
		fmt.Printf("DOOFUS SET A VALID CIPHER ALG (%d)\n", copts)
		err = errors.New("hkexchan: INVALID CIPHER ALG")
		//os.Exit(1)
	}

	hopts := (hc.cipheropts >> 8) & 0xFF
	switch hopts {
	case HmacSHA256:
		log.Printf("[hash HmacSHA256 (%d)]\n", hopts)
		halg := crypto.SHA256
		mc = halg.New()
		if !halg.Available() {
			log.Fatal("hash not available!")
		}
	case HmacSHA512:
		log.Printf("[hash HmacSHA512 (%d)]\n", hopts)
		halg := crypto.SHA512
		mc = halg.New()
		if !halg.Available() {
			log.Fatal("hash not available!")
		}
	default:
		log.Printf("[invalid hmac (%d)]\n", hopts)
		fmt.Printf("DOOFUS SET A VALID HMAC ALG (%d)\n", hopts)
		err = errors.New("hkexchan: INVALID HMAC ALG")
		return
		//os.Exit(1)
	}

	if err != nil {
		// Feed the IV into the hmac: all traffic in the connection must
		// feed its data into the hmac afterwards, so both ends can xor
		// that with the stream to detect corruption.
		_, _ = mc.Write(iv)
		var currentHash []byte
		currentHash = mc.Sum(currentHash)
		log.Printf("Channel init hmac(iv):%s\n", hex.EncodeToString(currentHash))
	}
	return
}
