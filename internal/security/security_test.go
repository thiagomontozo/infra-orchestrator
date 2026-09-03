package security

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, e := HashPassword("a long unique passphrase")
	if e != nil {
		t.Fatal(e)
	}
	if !VerifyPassword("a long unique passphrase", h) || VerifyPassword("wrong", h) {
		t.Fatal("password verification failed")
	}
	for _, s := range []string{"", "$argon2id$v=19$m=999999999,t=3,p=2$a$b", h + "$extra"} {
		if VerifyPassword("x", s) {
			t.Fatal("malformed hash accepted")
		}
	}
	if _, e = HashPassword("short"); e == nil {
		t.Fatal("weak password accepted")
	}
}
func TestCipherAAD(t *testing.T) {
	c, e := NewCipher(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	v, e := c.Encrypt("id", []byte("secret"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Decrypt("id", v)
	if e != nil || string(b) != "secret" {
		t.Fatal("decrypt failed")
	}
	if _, e = c.Decrypt("other", v); e == nil {
		t.Fatal("swapped ciphertext accepted")
	}
	if _, e = c.Decrypt("id", v[:len(v)-2]+"AA"); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestTOTPRFC(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(59, 0)
	if TOTP(secret, 1) != "287082" {
		t.Fatal("RFC vector failed")
	}
	step, ok := VerifyTOTP(secret, "287082", now, -1)
	if !ok || step != 1 {
		t.Fatal("valid code denied")
	}
	if _, ok = VerifyTOTP(secret, "287082", now, step); ok {
		t.Fatal("replay accepted")
	}
}
func TestRedaction(t *testing.T) {
	s := "Authorization: Bearer abc123\npassword=hunter2\npostgres://bob:secret@db/app\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
	out := Redact(s)
	for _, secret := range []string{"hunter2", "bob:secret", "eyJhbG", "abc123"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked: %s", secret)
		}
	}
	if got := Bounded("abc\ndef\nghi", 4, 2); !strings.Contains(got, "TRUNCATED") {
		t.Fatal("budget not applied")
	}
}
func TestNetworkPolicy(t *testing.T) {
	p, e := NewNetworkPolicy([]string{"10.0.0.0/8", "127.0.0.1/32"})
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"169.254.169.254", "0.0.0.0", "224.0.0.1", "8.8.8.8", "::ffff:169.254.169.254"} {
		if p.AllowedIP(netip.MustParseAddr(s)) {
			t.Fatal("SSRF allowed", s)
		}
	}
	if !p.AllowedIP(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("explicit private CIDR denied")
	}
	for _, u := range []string{"file:///etc/passwd", "http://user:pass@host", "gopher://host"} {
		if p.ValidateURL(u) == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
}

func TestInspectRedactionPreservesJSON(t *testing.T) {
	raw := `{"Name":"api","Config":{"Env":["ARBITRARY=confidential-value"],"Labels":{"api_key":"sensitive-value"}},"metadata":{"name":"keep"}}`
	got := SanitizeText(raw)
	if strings.Contains(got, "confidential-value") || strings.Contains(got, "sensitive-value") || !strings.Contains(got, "keep") {
		t.Fatal(got)
	}
}
