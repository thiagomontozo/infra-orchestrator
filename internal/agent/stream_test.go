package agent

import (
	"strings"
	"testing"
)

func TestJSONStringFieldReadsAnUnfinishedDocument(t *testing.T) {
	cases := []struct {
		buf, field, want string
		complete         bool
	}{
		{`{"thought":"vou olhar o processo","command":"ps aux"}`, "thought", "vou olhar o processo", true},
		{`{"thought": "com espaço"`, "thought", "com espaço", true},
		{`{"thought":"vou olh`, "thought", "vou olh", false},
		{`{"thought":"linha1\nlinha2"}`, "thought", "linha1\nlinha2", true},
		{`{"thought":"café quente"}`, "thought", "café quente", true},
		{`{"thought":"aspas \" no meio"}`, "thought", `aspas " no meio`, true},
		{`{"command":"ps","reply":"pronto"}`, "reply", "pronto", true},
		{`{"command":"ps"}`, "thought", "", false},
		{`{"thought":`, "thought", "", false},
	}
	for _, c := range cases {
		got, complete := jsonStringField(c.buf, c.field)
		if got != c.want || complete != c.complete {
			t.Fatalf("field %q of %q: got (%q,%v), want (%q,%v)", c.field, c.buf, got, complete, c.want, c.complete)
		}
	}
	// A truncated escape must wait for the rest instead of emitting a broken rune.
	for _, buf := range []string{`{"thought":"a\`, `{"thought":"a\u00`, `{"thought":"a\u00e`} {
		if got, complete := jsonStringField(buf, "thought"); got != "a" || complete {
			t.Fatalf("truncated escape %q produced (%q,%v)", buf, got, complete)
		}
	}
}

// feed simulates a streamed document arriving one byte at a time and returns everything
// the field emitted, in order.
func feed(field, document string) []string {
	f := &fieldStream{field: field}
	out := []string{}
	for i := 1; i <= len(document); i++ {
		if text := f.next(document[:i]); text != "" {
			out = append(out, text)
		}
	}
	return out
}

func TestFieldStreamEmitsEachCharacterOnce(t *testing.T) {
	document := `{"thought":"olhando os processos do container","command":"ps aux","reply":""}`
	parts := feed("thought", document)
	if joined := strings.Join(parts, ""); joined != "olhando os processos do container" {
		t.Fatalf("stream did not reconstruct the field: %q", joined)
	}
	if len(parts) < 5 {
		t.Fatalf("field arrived in %d chunk(s); prose should stream as it is written, not at the end", len(parts))
	}
}

func TestFieldStreamWithholdsAHalfWrittenSecret(t *testing.T) {
	document := `{"reply":"o arquivo tem password=hunter2seguro e mais nada"}`
	joined := strings.Join(feed("reply", document), "")
	if strings.Contains(joined, "hunter2") {
		t.Fatalf("a secret leaked through the live stream one character at a time: %q", joined)
	}
	if !strings.Contains(joined, "[REDACTED]") || !strings.HasPrefix(joined, "o arquivo tem ") {
		t.Fatalf("surrounding prose should survive redaction: %q", joined)
	}
	// The text after the secret is held until the field closes, but must still arrive.
	if !strings.Contains(joined, "e mais nada") {
		t.Fatalf("text after the secret never arrived: %q", joined)
	}
}

func TestFieldStreamNeverRewinds(t *testing.T) {
	f := &fieldStream{field: "reply"}
	if first := f.next(`{"reply":"resposta completa"}`); first != "resposta completa" {
		t.Fatalf("first read wrong: %q", first)
	}
	if again := f.next(`{"reply":"resposta completa"}`); again != "" {
		t.Fatalf("the same text was emitted twice: %q", again)
	}
}
