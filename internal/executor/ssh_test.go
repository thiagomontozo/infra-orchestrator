package executor

import (
	"strings"
	"testing"
)

func TestNoShell(t *testing.T) {
	for _, p := range []string{"sh", "bash", "sudo", "ssh", "curl"} {
		if _, e := (Command{Program: p}).Render(); e == nil {
			t.Fatal("program allowed", p)
		}
	}
	s, e := (Command{Program: "docker", Args: []string{"restart", "a'; touch /tmp/pwn; '"}}).Render()
	if e != nil || !strings.Contains(s, `'"'"'`) {
		t.Fatal("argument not escaped")
	}
	for _, s := range []string{"--all", "$(id)", "a;rm -rf /", "../../etc", "a\nb"} {
		if ValidRef(s) {
			t.Fatal("unsafe reference", s)
		}
	}
}
func TestOutputBound(t *testing.T) {
	b := &capped{limit: 4}
	n, e := b.Write([]byte("123456"))
	if n != 6 || e != nil || b.b.String() != "1234" || !b.truncated {
		t.Fatal("output cap failed")
	}
}
