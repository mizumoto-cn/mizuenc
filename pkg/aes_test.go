package pkg

import (
	"bytes"
	"encoding/base64"
	"testing"
)

const (
	errEncryptFmt = "Encrypt: %v"
	errExpected   = "expected error"
)

func mustDecodeToken(t *testing.T, token []byte) []byte {
	t.Helper()
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(token)))
	n, err := base64.RawURLEncoding.Decode(dst, token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return dst[:n]
}

func encodeToken(blob []byte) []byte {
	s := base64.RawURLEncoding.EncodeToString(blob)
	return []byte(s)
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	e := DefaultEncrypter
	plaintext := []byte("hello mizuenc")

	token, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf(errEncryptFmt, err)
	}

	got, err := e.Decrypt(token)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	e := DefaultEncrypter
	if _, err := e.Decrypt([]byte("not-base64!!!")); err == nil {
		t.Fatalf(errExpected)
	}
}

func TestDecrypt_SignatureMismatch(t *testing.T) {
	e := DefaultEncrypter
	token, err := e.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf(errEncryptFmt, err)
	}

	blob := mustDecodeToken(t, token)
	if len(blob) == 0 {
		t.Fatalf("decoded blob is empty")
	}

	// Corrupt the last byte (inside signature suffix).
	blob[len(blob)-1] ^= 0xff

	if _, err := e.Decrypt(encodeToken(blob)); err == nil {
		t.Fatalf(errExpected)
	}
}

func TestDecrypt_VersionTagMismatch(t *testing.T) {
	e := DefaultEncrypter
	token, err := e.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf(errEncryptFmt, err)
	}

	blob := mustDecodeToken(t, token)
	vlen := len(e.versionTag)
	if len(blob) < vlen+e.signatureLen {
		t.Fatalf("blob too short for version+signature: %d", len(blob))
	}

	// Corrupt the versionTag prefix; keep the signature suffix intact.
	blob[0] ^= 0xff

	if _, err := e.Decrypt(encodeToken(blob)); err == nil {
		t.Fatalf(errExpected)
	}
}

func TestDecrypt_CiphertextTamper(t *testing.T) {
	e := DefaultEncrypter
	token, err := e.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf(errEncryptFmt, err)
	}

	blob := mustDecodeToken(t, token)

	// Layout: versionTag + salt + nonce + ciphertext + signature
	off := len(e.versionTag) + e.saltLen + e.nonceLen
	end := len(blob) - e.signatureLen
	if off >= end {
		t.Fatalf("invalid layout: off=%d end=%d", off, end)
	}

	// Flip one byte inside ciphertext.
	blob[off] ^= 0xff

	if _, err := e.Decrypt(encodeToken(blob)); err == nil {
		t.Fatalf(errExpected)
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	e := DefaultEncrypter

	// Decodes to 2 bytes, definitely shorter than signatureLen.
	token := encodeToken([]byte("hi"))
	if _, err := e.Decrypt(token); err == nil {
		t.Fatalf(errExpected)
	}
}
