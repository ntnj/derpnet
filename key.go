package derpnet

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

type Key []byte
type PublicKey []byte

func (k Key) IsValid() bool {
	return len(k) == 32
}

func (k Key) PublicKey() (PublicKey, error) {
	pubKey, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (k Key) Bytes() []byte {
	return k
}

func (p PublicKey) Bytes() []byte {
	return p
}

func GenerateKey() (Key, error) {
	key := make([]byte, 32)
	if n, err := rand.Read(key); n != 32 || err != nil {
		return nil, err
	}
	// Clamp the key: https://cr.yp.to/ecdh.html
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}
