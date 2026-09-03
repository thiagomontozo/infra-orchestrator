package operations

import (
	"context"
	"encoding/json"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
)

// TargetHash binds approval to connection identity and resource addressing, not live status.
func (e *Engine) TargetHash(ctx context.Context, h domain.Host, r domain.Resource) (string, error) {
	connection := func(x domain.Host) any {
		return []any{x.ID, x.Hostname, x.Port, x.Username, x.AuthMethod, x.SecretID, x.Fingerprint, x.Environment, x.BastionID}
	}
	target := []any{connection(h), r.ExternalID, r.Namespace, r.Provider, r.Type, r.Metadata["project"], r.Metadata["service"]}
	if h.BastionID != "" {
		b, err := e.DB.Host(ctx, h.BastionID)
		if err != nil {
			return "", err
		}
		target = append(target, connection(b))
	}
	b, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	return security.HashToken(string(b)), nil
}
