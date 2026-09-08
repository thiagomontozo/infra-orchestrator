package llm

import (
	"bufio"
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

// Delta is one increment of a streamed completion. Content is the answer itself;
// Reasoning is the separate channel some models emit while they think, which never
// appears in Content and is not part of the JSON the caller has to parse.
type Delta struct{ Content, Reasoning string }

type Provider interface {
	Models(context.Context) ([]string, error)
	Complete(context.Context, []Message) (string, error)
	Stream(context.Context, []Message, func(Delta)) (string, error)
}

const responseLimit = 1024 * 1024

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

// send performs the request and hands back the open response. Callers that read the body
// in full go through request; only the streaming path keeps the body open.
func (p *OpenAI) send(ctx context.Context, method, path string, body any) (*http.Response, error) {
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
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		res.Body.Close()
		return nil, fmt.Errorf("LLM provider HTTP %d", res.StatusCode)
	}
	return res, nil
}
func (p *OpenAI) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	ctx, span := otel.Tracer("llm").Start(ctx, "llm.request")
	defer span.End()
	res, e := p.send(ctx, method, path, body)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	out, e := io.ReadAll(io.LimitReader(res.Body, responseLimit+1))
	if e != nil {
		return nil, e
	}
	if len(out) > responseLimit {
		return nil, fmt.Errorf("LLM response exceeded limit")
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
	body, tokens := p.body(m, false)
	b, e := p.request(ctx, "POST", "/chat/completions", body)
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

// body builds the chat request shared by Complete and Stream, so a streamed turn and a
// buffered one cannot drift in model, temperature or response format.
func (p *OpenAI) body(m []Message, stream bool) (map[string]any, int) {
	tokens := p.MaxTokens
	if tokens == 0 {
		tokens = 1500
	}
	out := map[string]any{"model": p.Model, "messages": m, "temperature": 0.1, "max_tokens": tokens, "response_format": map[string]string{"type": "json_object"}}
	if stream {
		out["stream"] = true
	}
	return out, tokens
}

// Stream reads a server-sent completion, calling onDelta for every increment as it
// arrives, and returns the full content once the stream ends. The return value is exactly
// what Complete would have produced, so callers parse the result the same way whether or
// not anybody was watching.
func (p *OpenAI) Stream(ctx context.Context, m []Message, onDelta func(Delta)) (string, error) {
	ctx, span := otel.Tracer("llm").Start(ctx, "llm.stream")
	defer span.End()
	body, tokens := p.body(m, true)
	res, e := p.send(ctx, "POST", "/chat/completions", body)
	if e != nil {
		return "", e
	}
	defer res.Body.Close()
	var content strings.Builder
	finish := ""
	reader := bufio.NewReader(io.LimitReader(res.Body, responseLimit+1))
	for {
		line, e := reader.ReadString('\n')
		payload, found := strings.CutPrefix(strings.TrimSpace(line), "data:")
		if found {
			payload = strings.TrimSpace(payload)
			if payload == "[DONE]" {
				break
			}
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content          string `json:"content"`
						Reasoning        string `json:"reasoning"`
						ReasoningContent string `json:"reasoning_content"`
					} `json:"delta"`
					FinishReason string `json:"finish_reason"`
				} `json:"choices"`
			}
			// A chunk that does not decode is a keepalive or a field this client does not
			// model; the stream continues rather than failing the whole turn.
			if json.Unmarshal([]byte(payload), &chunk) == nil && len(chunk.Choices) > 0 {
				c := chunk.Choices[0]
				if c.FinishReason != "" {
					finish = c.FinishReason
				}
				reasoning := c.Delta.Reasoning + c.Delta.ReasoningContent
				if c.Delta.Content != "" || reasoning != "" {
					content.WriteString(c.Delta.Content)
					if content.Len() > responseLimit {
						return "", fmt.Errorf("LLM response exceeded limit")
					}
					if onDelta != nil {
						onDelta(Delta{Content: c.Delta.Content, Reasoning: reasoning})
					}
				}
			}
		}
		if e != nil {
			if e == io.EOF {
				break
			}
			return "", e
		}
	}
	if finish == "length" {
		return "", fmt.Errorf("LLM response truncated at max_tokens (%d)", tokens)
	}
	if content.Len() == 0 {
		return "", fmt.Errorf("LLM returned no completion")
	}
	return security.Redact(content.String()), nil
}
