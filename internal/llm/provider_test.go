package llm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIProtocol(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer example-test-key" {
			t.Error("missing authorization")
		}
		switch r.URL.Path {
		case "/v1/models":
			io.WriteString(w, `{"data":[{"id":"local-model"}]}`)
		case "/v1/chat/completions":
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"summary\":\"ok\"}"}}]}`)
		default:
			t.Error(r.URL.Path)
		}
	}))
	defer server.Close()
	p := &OpenAI{BaseURL: server.URL, Model: "local-model", APIKey: "example-test-key", Client: server.Client()}
	m, e := p.Models(context.Background())
	if e != nil || len(m) != 1 {
		t.Fatal(e, m)
	}
	s, e := p.Complete(context.Background(), []Message{{Role: "user", Content: "diagnose"}})
	if e != nil || !strings.Contains(s, "summary") {
		t.Fatal(e, s)
	}
}
