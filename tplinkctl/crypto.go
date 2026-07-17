// Package crypto implements the exact primitives the TP-Link router web UI
// uses (see libs/encrypt.js and libs/tpEncrypt.js):
//
//   - AES-128-CBC / PKCS7, where the key and IV are the UTF-8 bytes of
//     16-character ASCII strings (CryptoJS.enc.Utf8.parse semantics).
//   - RSA PKCS#1 v1.5 "type 2" encryption padding, with long inputs split
//     into fixed-size chunks and the hex blocks concatenated (the JS
//     getSignature() chunking).
//   - MD5 / SHA-256 credential hashing.
package main 

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// PublicKey is an RSA public key parsed from the router's (n_hex, e_hex) pair.
type PublicKey struct {
	key      *rsa.PublicKey
	sizeHex  int // modulus size in hex chars (== bytes*2)
	maxChunk int // max plaintext bytes per block (k - 11 for PKCS#1 v1.5)
}

// ParsePublicKey builds an RSA public key from hex modulus and exponent,
// exactly as encrypt.js setPublic(n, e) does.
func ParsePublicKey(nHex, eHex string) (*PublicKey, error) {
	n, ok := new(big.Int).SetString(nHex, 16)
	if !ok {
		return nil, fmt.Errorf("invalid RSA modulus hex")
	}
	e, ok := new(big.Int).SetString(eHex, 16)
	if !ok {
		return nil, fmt.Errorf("invalid RSA exponent hex")
	}
	k := (n.BitLen() + 7) / 8
	return &PublicKey{
		key:      &rsa.PublicKey{N: n, E: int(e.Int64())},
		sizeHex:  k * 2,
		maxChunk: k - 11,
	}, nil
}

// EncryptChunked RSA-encrypts msg in maxChunk-sized pieces, concatenating the
// hex of each block (left-padded to the modulus byte length). This matches
// both su.encrypt (single password block) and getSignature (53-byte chunks).
func (p *PublicKey) EncryptChunked(msg string) (string, error) {
	raw := []byte(msg)
	var b strings.Builder
	for i := 0; i < len(raw); i += p.maxChunk {
		end := min(i + p.maxChunk, len(raw))
		ct, err := rsa.EncryptPKCS1v15(rand.Reader, p.key, raw[i:end])
		if err != nil {
			return "", err
		}
		h := hex.EncodeToString(ct)
		// left-pad to fixed block width (JS zero-pads short blocks)
		if len(h) < p.sizeHex {
			h = strings.Repeat("0", p.sizeHex-len(h)) + h
		}
		b.WriteString(h)
	}
	return b.String(), nil
}

// AESEncryptB64 performs AES-128-CBC + PKCS7 and returns base64, matching
// CryptoJS.AES.encrypt(plaintext, Utf8(key), {iv: Utf8(iv)}).toString().
// key and iv must each be 16 ASCII characters.
func AESEncryptB64(plaintext, key, iv string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	if len(iv) != aes.BlockSize {
		return "", fmt.Errorf("iv must be 16 bytes, got %d", len(iv))
	}
	data := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, []byte(iv)).CryptBlocks(out, data)
	return base64.StdEncoding.EncodeToString(out), nil
}

// AESDecryptB64 reverses AESEncryptB64 — used to decrypt router responses.
func AESDecryptB64(ciphertextB64, key, iv string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not a multiple of block size")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, []byte(iv)).CryptBlocks(out, data)
	unpadded, err := pkcs7Unpad(out)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

// HashCredential computes MD5(username+password), or SHA-256 if isRGSec
// (the IS_RG_SEC branch in tpEncrypt.js setHash).
func HashCredential(username, password string, isRGSec bool) string {
	data := []byte(username + password)
	if isRGSec {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// RandDigits returns n random ASCII digits, matching
// tpEncrypt.js generateRandomIntString(n).
func RandDigits(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = '0' + (b % 10)
	}
	return string(out), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > len(data) {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	return data[:len(data)-pad], nil
}
