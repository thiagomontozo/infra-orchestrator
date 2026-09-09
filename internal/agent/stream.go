package agent

import (
	"context"
	"github.com/thiagomontozo/infra-orchestrator/internal/llm"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"log/slog"
	"strconv"
	"strings"
	"unicode/utf8"
)

// secretPrefixes are the tokens that open a redaction pattern. A pattern cannot be
// recognized until its value has arrived, so while one of these sits unmatched at the tail
// of a growing field, everything from it onward is held back: half a secret is still a
// secret. Matching them against the already-redacted text means a trigger only shows up
// here while its value is still in flight.
var secretPrefixes = []string{"authorization", "bearer", "basic", "api key", "api_key", "api-key", "apikey", "password", "passwd", "secret", "cookie", "token", "eyj", "sk-", "ghp_", "gho_", "akia", "-----begin", "http", "postgres", "mysql", "mongodb", "redis", "amqp", "://"}

// holdFrom returns the offset from which a still-growing field must be withheld: the
// earliest unmatched secret trigger, or a trigger that is itself only half written at the
// tail, since the next character may complete it. With neither, the whole string is safe.
func holdFrom(s string) int {
	lower := strings.ToLower(s)
	cut := len(s)
	for _, prefix := range secretPrefixes {
		if i := strings.Index(lower, prefix); i >= 0 && i < cut {
			cut = i
		}
		for n := min(len(prefix)-1, len(lower)); n > 0; n-- {
			if strings.HasSuffix(lower, prefix[:n]) {
				if i := len(lower) - n; i < cut {
					cut = i
				}
				break
			}
		}
	}
	return cut
}

// ChatEvent is one increment of a chat turn, as it happens. The same turn produces the
// same events whether or not anyone is watching; without a listener they are discarded.
type ChatEvent struct {
	Type    string `json:"type"`
	Text    string `json:"text,omitempty"`
	Step    int    `json:"step,omitempty"`
	Command string `json:"command,omitempty"`
	Status  string `json:"status,omitempty"`
	Output  string `json:"output,omitempty"`
	Seconds int    `json:"seconds,omitempty"`
}

// Emitter receives chat events as the turn unfolds. A nil Emitter means nobody is
// watching, which is the non-streaming path.
type Emitter func(ChatEvent)

func (e Emitter) emit(v ChatEvent) {
	if e != nil {
		e(v)
	}
}

// jsonStringField decodes the value of a top-level string field out of a JSON document
// that may still be arriving, and reports whether its closing quote has been seen. It
// exists because the model answers in JSON but a person wants to read the prose inside it
// while it is being written, not after.
func jsonStringField(buf, field string) (string, bool) {
	key := `"` + field + `"`
	i := strings.Index(buf, key)
	if i < 0 {
		return "", false
	}
	i += len(key)
	for i < len(buf) && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r') {
		i++
	}
	if i >= len(buf) || buf[i] != ':' {
		return "", false
	}
	i++
	for i < len(buf) && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r') {
		i++
	}
	if i >= len(buf) || buf[i] != '"' {
		return "", false
	}
	var out strings.Builder
	for i++; i < len(buf); i++ {
		switch c := buf[i]; c {
		case '"':
			return out.String(), true
		case '\\':
			// An escape that has not fully arrived yet: stop and wait for the rest.
			if i+1 >= len(buf) {
				return out.String(), false
			}
			switch buf[i+1] {
			case 'n':
				out.WriteByte('\n')
			case 't':
				out.WriteByte('\t')
			case 'r':
				out.WriteByte('\r')
			case 'b', 'f':
			case 'u':
				if i+5 >= len(buf) {
					return out.String(), false
				}
				n, e := strconv.ParseUint(buf[i+2:i+6], 16, 32)
				if e != nil {
					return out.String(), false
				}
				out.WriteRune(rune(n))
				i += 4
			default:
				out.WriteByte(buf[i+1])
			}
			i++
		default:
			out.WriteByte(c)
		}
	}
	return out.String(), false
}

// fieldStream turns the growing value of one JSON field into a sequence of increments,
// each already redacted. It never emits the same text twice and never rewinds.
type fieldStream struct {
	field string
	sent  string
}

// next returns the part of the field that has arrived since the last call. While the
// field is still open the tail is withheld from the first unmatched secret trigger, so a
// half-written secret cannot slip out ahead of the redaction that would catch it whole.
func (f *fieldStream) next(buf string) string {
	value, complete := jsonStringField(buf, f.field)
	if value == "" {
		return ""
	}
	visible := security.Redact(value)
	if !complete {
		visible = visible[:holdFrom(visible)]
		// Never cut a multi-byte character in half on its way to the browser.
		for len(visible) > 0 && !utf8.ValidString(visible) {
			visible = visible[:len(visible)-1]
		}
	}
	// Redaction rewrites text that may already have been sent, and the live view must not
	// splice a diff onto something that changed underneath it. When that happens the
	// stream simply stops advancing; the stored message is redacted whole and stays right.
	if len(visible) <= len(f.sent) || !strings.HasPrefix(visible, f.sent) {
		return ""
	}
	out := visible[len(f.sent):]
	f.sent = visible
	return out
}

// streamTurn asks the model for one turn, forwarding the prose inside the JSON to the
// watcher as it is written. With no watcher it falls back to the buffered call, so the
// non-streaming API keeps exactly the behaviour it had.
func streamTurn(ctx context.Context, provider llm.Provider, messages []llm.Message, emit Emitter) (string, error) {
	if emit == nil {
		return provider.Complete(ctx, messages)
	}
	var buf strings.Builder
	shown := false
	thought, reply := &fieldStream{field: "thought"}, &fieldStream{field: "reply"}
	raw, e := provider.Stream(ctx, messages, func(d llm.Delta) {
		shown = true
		if d.Reasoning != "" {
			emit(ChatEvent{Type: "reasoning", Text: security.Redact(d.Reasoning)})
		}
		if d.Content == "" {
			return
		}
		buf.WriteString(d.Content)
		current := buf.String()
		if text := thought.next(current); text != "" {
			emit(ChatEvent{Type: "thought", Text: text})
		}
		if text := reply.next(current); text != "" {
			emit(ChatEvent{Type: "reply", Text: text})
		}
	})
	if e != nil {
		// A provider that cannot stream still has to work. Nothing reached the watcher
		// yet, so the turn is retried whole and delivered in one piece below; once
		// anything has been shown, a failure is a real failure.
		if shown {
			return "", e
		}
		slog.Info("LLM provider did not stream; falling back to a buffered turn", "error", e)
		if raw, e = provider.Complete(ctx, messages); e != nil {
			return "", e
		}
	}
	// Release whatever the hold-back was still withholding when the stream ended.
	if text := thought.next(raw); text != "" {
		emit(ChatEvent{Type: "thought", Text: text})
	}
	if text := reply.next(raw); text != "" {
		emit(ChatEvent{Type: "reply", Text: text})
	}
	return raw, nil
}
