package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"go.opentelemetry.io/otel"
	"io"
	"net/http"
	"strings"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Provider interface {
	Models(context.Context) ([]string, error)
	Complete(context.Context, []Message) (string, error)
}
type OpenAI struct {
	BaseURL, Model, APIKey string
	Client                 *http.Client
	MaxTokens              int
}

func (p *OpenAI) endpoint(path string) string {
	base := strings.TrimRight(p.BaseURL, "/")
	if !strings.HasSuffix(base, "/v1") {
		base += "/v1"
	}
	return base + path
}
func (p *OpenAI) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	ctx, span := otel.Tracer("llm").Start(ctx, "llm.request")
	defer span.End()
	var b bytes.Buffer
	if body != nil {
		if e := json.NewEncoder(&b).Encode(body); e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, p.endpoint(path), &b)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	res, e := p.Client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	out, e := io.ReadAll(io.LimitReader(res.Body, 1024*1024+1))
	if e != nil {
		return nil, e
	}
	if len(out) > 1024*1024 {
		return nil, fmt.Errorf("LLM response exceeded limit")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("LLM provider HTTP %d", res.StatusCode)
	}
	return out, nil
}
func (p *OpenAI) Models(ctx context.Context) ([]string, error) {
	b, e := p.request(ctx, "GET", "/models", nil)
	if e != nil {
		return nil, e
	}
	var res struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if e = json.Unmarshal(b, &res); e != nil {
		return nil, e
	}
	out := []string{}
	for _, v := range res.Data {
		out = append(out, v.ID)
	}
	return out, nil
}
func (p *OpenAI) Complete(ctx context.Context, m []Message) (string, error) {
	tokens := p.MaxTokens
	if tokens == 0 {
		tokens = 1500
	}
	b, e := p.request(ctx, "POST", "/chat/completions", map[string]any{"model": p.Model, "messages": m, "temperature": 0.1, "max_tokens": tokens, "response_format": map[string]string{"type": "json_object"}})
	if e != nil {
		return "", e
	}
	var res struct {
		Choices []struct {
			Message      Message `json:"message"`
			FinishReason string  `json:"finish_reason"`
		} `json:"choices"`
	}
	if e = json.Unmarshal(b, &res); e != nil {
		return "", e
	}
	if len(res.Choices) == 0 {
		return "", fmt.Errorf("LLM returned no completion")
	}
	if res.Choices[0].FinishReason == "length" {
		return "", fmt.Errorf("LLM response truncated at max_tokens (%d)", tokens)
	}
	return security.Redact(res.Choices[0].Message.Content), nil
}
