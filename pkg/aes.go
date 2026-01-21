package pkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

var DefaultEncrypter = new(aesEncrypter)

type Encrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type aesEncrypter struct {
	name         string
	versionTag   string
	saltLen      int
	nonceLen     int
	iter         int
	keyLen       int
	signatureLen int
	signature    string
}

func init() {
	DefaultEncrypter.versionTag = "v1.0.0"
	DefaultEncrypter.name = "xuruiyuan"
	DefaultEncrypter.saltLen = 16
	DefaultEncrypter.nonceLen = 12
	DefaultEncrypter.iter = 100_000
	DefaultEncrypter.keyLen = 32 // AES-256
	DefaultEncrypter.signature = "This message is encrypted by Mizu-encrypt, using AES-256-GCM algorithm with args as follows: " +
		DefaultEncrypter.name + "|" +
		DefaultEncrypter.versionTag + "|" +
		strconv.Itoa(DefaultEncrypter.saltLen) + "|" +
		strconv.Itoa(DefaultEncrypter.nonceLen) + "|" +
		strconv.Itoa(DefaultEncrypter.iter) + "|" +
		strconv.Itoa(DefaultEncrypter.keyLen) + "|"
	DefaultEncrypter.signatureLen = len(DefaultEncrypter.signature)
}

// Encrypt 将明文加密成 base64 token： v1|salt|nonce|ciphertext -> base64
func (e *aesEncrypter) Encrypt(plaintext []byte) ([]byte, error) {
	salt := make([]byte, e.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(e.name), salt, e.iter, e.keyLen, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, e.nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// AAD（附加认证数据）：把版本也纳入认证，避免被替换
	aad := []byte(e.versionTag)

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// 拼包： [versionTag bytes] + salt + nonce + ciphertext
	blob := make([]byte, 0, len(e.versionTag)+e.saltLen+e.nonceLen+len(ciphertext))
	blob = append(blob, []byte(e.versionTag)...)
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	blob = append(blob, []byte(e.signature)...)
	// 用 URL-safe Base64，复制粘贴更舒服
	token := base64.RawURLEncoding.EncodeToString(blob)
	return []byte(token), nil
}

func (e *aesEncrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(ciphertext)))
	n, err := base64.RawURLEncoding.Decode(dst, ciphertext)
	if err != nil {
		return nil, err
	}
	blob := dst[:n]

	// 先验签名（防止被随意拼接/截断）
	if len(blob) < e.signatureLen {
		return nil, errors.New("ciphertext is too short")
	}
	if !bytes.HasSuffix(blob, []byte(e.signature)) {
		return nil, errors.New("signature mismatch")
	}
	blob = blob[:len(blob)-e.signatureLen]

	// 解析： [versionTag bytes] + salt + nonce + ciphertext
	minLen := len(e.versionTag) + e.saltLen + e.nonceLen + 1
	if len(blob) < minLen {
		return nil, errors.New("ciphertext is too short")
	}

	gotVersion := string(blob[:len(e.versionTag)])
	if gotVersion != e.versionTag {
		return nil, errors.New("version tag mismatch")
	}

	off := len(e.versionTag)
	salt := blob[off : off+e.saltLen]
	off += e.saltLen
	nonce := blob[off : off+e.nonceLen]
	off += e.nonceLen
	ct := blob[off:]

	key := pbkdf2.Key([]byte(e.name), salt, e.iter, e.keyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// AAD 必须与 Encrypt 时一致
	aad := []byte(gotVersion)
	plaintext, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
