package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/argon2"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func Random(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func HashToken(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func HashPassword(p string) (string, error) {
	if len(p) < 12 || len(p) > 1024 {
		return "", fmt.Errorf("password must contain 12..1024 bytes")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	h := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h)), nil
}
func VerifyPassword(p, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=2" || len(p) > 1024 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[4])
	if e != nil || len(salt) != 16 {
		return false
	}
	expected, e := base64.RawStdEncoding.DecodeString(parts[5])
	if e != nil || len(expected) != 32 {
		return false
	}
	h := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(expected, h) == 1
}

type Cipher struct{ aead cipher.AEAD }

func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires 32 bytes")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	return &Cipher{a}, e
}
func (c *Cipher) Encrypt(id string, b []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(c.aead.Seal(nonce, nonce, b, []byte(id))), nil
}
func (c *Cipher) Decrypt(id, s string) ([]byte, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) < c.aead.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return c.aead.Open(nil, b[:c.aead.NonceSize()], b[c.aead.NonceSize():], []byte(id))
}
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
func TOTP(secret string, step int64) string {
	k, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(step))
	h := hmac.New(sha1.New, k)
	h.Write(b[:])
	v := h.Sum(nil)
	offset := v[len(v)-1] & 15
	n := binary.BigEndian.Uint32(v[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}
func VerifyTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	if _, e := strconv.Atoi(code); e != nil {
		return 0, false
	}
	for _, d := range []int64{0, -1, 1} {
		step := now.Unix()/30 + d
		if step > last && subtle.ConstantTimeCompare([]byte(TOTP(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

var redactions = []*regexp.Regexp{
	regexp.MustCompile(`(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(?:authorization|bearer|api[_-]?key|password|passwd|secret|cookie|token)\s*[=: ]\s*[^\s,;]+`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s]+`),
	regexp.MustCompile(`(?i)https?://[^\s/@]+:[^\s/@]+@[^\s]+`),
	regexp.MustCompile(`\b(?:sk-|ghp_|gho_|AKIA)[A-Za-z0-9_-]{12,}\b`),
}

func Redact(s string) string {
	for _, r := range redactions {
		s = r.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
func Bounded(s string, maxBytes, maxLines int) string {
	lines := strings.SplitN(s, "\n", maxLines+1)
	truncated := len(lines) > maxLines
	if truncated {
		lines = lines[:maxLines]
	}
	s = strings.Join(lines, "\n")
	if len(s) > maxBytes {
		s = s[:maxBytes]
		truncated = true
	}
	s = strings.ToValidUTF8(s, "")
	if truncated {
		s += "\n[TRUNCATED]"
	}
	return s
}
