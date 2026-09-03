package security

import (
	"encoding/json"
	"regexp"
	"strings"
)

func SanitizeText(text string) string {
	var value any
	if json.Unmarshal([]byte(text), &value) == nil {
		b, e := json.MarshalIndent(SanitizeValue(value), "", "  ")
		if e == nil {
			return string(b)
		}
	}
	return Redact(text)
}

var secretField = regexp.MustCompile(`(?i)(password|passwd|secret|token|authorization|cookie|api.?key|private.?key|kubeconfig|connection.?string)`)

// SanitizeValue walks JSON-shaped data without corrupting JSON syntax. Environment arrays
// and Kubernetes Secret bodies are sensitive even when variable names do not look secret.
func SanitizeValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		if kind, ok := v["kind"].(string); ok && kind == "Secret" {
			return map[string]any{"kind": "Secret", "data": "[REDACTED]"}
		}
		for k, x := range v {
			if secretField.MatchString(k) || strings.EqualFold(k, "env") || strings.EqualFold(k, "stringData") {
				out[k] = "[REDACTED]"
			} else {
				out[k] = SanitizeValue(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = SanitizeValue(x)
		}
		return out
	case string:
		return Redact(v)
	default:
		return value
	}
}
