package hkexnet

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"net"

	"blitter.com/go/hkexsh/logger"
	kcp "github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

const (
	KCP_NONE = iota
	KCP_AES
	KCP_BLOWFISH
	KCP_CAST5
	KCP_SM4
	KCP_SALSA20
	KCP_SIMPLEXOR
	KCP_TEA
	KCP_3DES
	KCP_TWOFISH
	KCP_XTEA
)

// for github.com/xtaci/kcp-go BlockCrypt alg selection
type KCPAlg uint8

var (
	kcpKeyBytes  []byte = []byte("SET THIS") // symmetric crypto key for KCP (github.com/xtaci/kcp-go) if used
	kcpSaltBytes []byte = []byte("ALSO SET THIS")
)

func getKCPalgnum(extensions []string) (k KCPAlg) {
	k = KCP_AES // default
	var s string
	for _, s = range extensions {
		switch s {
		case "KCP_NONE":
			k = KCP_NONE
			break //out of for
		case "KCP_AES":
			k = KCP_AES
			break //out of for
		case "KCP_BLOWFISH":
			k = KCP_BLOWFISH
			break //out of for
		case "KCP_CAST5":
			k = KCP_CAST5
			break //out of for
		case "KCP_SM4":
			k = KCP_SM4
			break //out of for
		case "KCP_SALSA20":
			k = KCP_SALSA20
			break //out of for
		case "KCP_SIMPLEXOR":
			k = KCP_SIMPLEXOR
			break //out of for
		case "KCP_TEA":
			k = KCP_TEA
			break //out of for
		case "KCP_3DES":
			k = KCP_3DES
			break //out of for
		case "KCP_TWOFISH":
			k = KCP_TWOFISH
			break //out of for
		case "KCP_XTEA":
			k = KCP_XTEA
			break //out of for
		}
	}
	logger.LogDebug(fmt.Sprintf("[KCP BlockCrypt '%s' activated]", s))
	return
}

func SetKCPKeyAndSalt(key []byte, salt []byte) {
	kcpKeyBytes = key
	kcpSaltBytes = salt
}

func _newKCPBlockCrypt(key []byte, extensions []string) (b kcp.BlockCrypt, e error) {
	switch getKCPalgnum(extensions) {
	case KCP_NONE:
		return kcp.NewNoneBlockCrypt(key)
	case KCP_AES:
		return kcp.NewAESBlockCrypt(key)
	case KCP_BLOWFISH:
		return kcp.NewBlowfishBlockCrypt(key)
	case KCP_CAST5:
		return kcp.NewCast5BlockCrypt(key)
	case KCP_SM4:
		return kcp.NewSM4BlockCrypt(key)
	case KCP_SALSA20:
		return kcp.NewSalsa20BlockCrypt(key)
	case KCP_SIMPLEXOR:
		return kcp.NewSimpleXORBlockCrypt(key)
	case KCP_TEA:
		return kcp.NewTEABlockCrypt(key)
	case KCP_3DES:
		return kcp.NewTripleDESBlockCrypt(key)
	case KCP_TWOFISH:
		return kcp.NewTwofishBlockCrypt(key)
	case KCP_XTEA:
		return kcp.NewXTEABlockCrypt(key)
	}
	return nil, errors.New("Invalid KCP BlockCrypto specified")
}

func kcpDial(ipport string, extensions []string) (c net.Conn, err error) {
	kcpKey := pbkdf2.Key(kcpKeyBytes, kcpSaltBytes, 1024, 32, sha1.New)
	block, be := _newKCPBlockCrypt([]byte(kcpKey), extensions)
	_ = be
	return kcp.DialWithOptions(ipport, block, 10, 3)
}

func kcpListen(ipport string, extensions []string) (l net.Listener, err error) {
	kcpKey := pbkdf2.Key(kcpKeyBytes, kcpSaltBytes, 1024, 32, sha1.New)
	block, be := _newKCPBlockCrypt([]byte(kcpKey), extensions)
	_ = be
	return kcp.ListenWithOptions(ipport, block, 10, 3)
}

func (hl *HKExListener) AcceptKCP() (c net.Conn, e error) {
	return hl.l.(*kcp.Listener).AcceptKCP()
}
