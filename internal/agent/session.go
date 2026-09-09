package agent

import (
	"context"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/llm"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"time"
)

const (
	// execOutput bounds what a single command contributes to the next prompt. A command
	// that prints more than this is truncated for the model, never re-run.
	execOutput      = 6000
	execOutputLines = 200
	// execBudget caps how many commands one person can have the agent run per hour,
	// across every session and conversation.
	execBudget = 60
)

// containerSession is one authorized agent session pinned to a single container: the
// resource it targets, the host that reaches it, and the model it talks to. Everything
// after openSession trusts these fields, and nothing the model returns can change them.
type containerSession struct {
	ID         string
	ProviderID string
	Container  string
	Resource   domain.Resource
	Host       domain.Host
	Provider   llm.Provider
}

// openSession authorizes a session and resolves its container. Commands inside a session
// are free-form, so this is the single place authorization happens: the caller needs
// llm.use, resource.read and the provider's exec permission in the host's environment,
// which is exactly what the interactive console already requires of them.
func (r *Runtime) openSession(ctx context.Context, p domain.Principal, resourceID, providerID string) (containerSession, error) {
	var s containerSession
	if r.Exec == nil {
		return s, fmt.Errorf("remote executor unavailable")
	}
	resource, e := r.DB.Resource(ctx, resourceID)
	if e != nil {
		return s, e
	}
	host, e := r.DB.Host(ctx, resource.HostID)
	if e != nil {
		return s, e
	}
	exec := rbac.Permission(resource.Provider, "exec")
	if !rbac.Allowed(p, "llm.use", host.Environment) || !rbac.Allowed(p, "resource.read", host.Environment) {
		return s, operations.Denied{Reason: "AI/resource permission denied"}
	}
	if !rbac.Allowed(p, exec, host.Environment) {
		return s, operations.Denied{Reason: "the agent needs the " + exec + " permission in " + host.Environment}
	}
	if resource.State == "missing" {
		return s, fmt.Errorf("resource is no longer present; run discovery")
	}
	_, container, e := adapters.ConsoleTarget(resource)
	if e != nil {
		return s, e
	}
	provider, config, e := r.provider(ctx, providerID)
	if e != nil {
		return s, e
	}
	if config.Environment != "" && config.Environment != host.Environment {
		return s, operations.Denied{Reason: "provider environment denied"}
	}
	return containerSession{ID: domain.ID(), ProviderID: providerID, Container: container, Resource: resource, Host: host, Provider: provider}, nil
}

// runCommand executes one command the model proposed, inside the session's container. It
// returns the transcript entry, the evidence to feed back into the conversation, and an
// error only when the session cannot continue. A command the backend rejects and a
// command that exits non-zero are both results the model reacts to, not failures.
func (r *Runtime) runCommand(ctx context.Context, p domain.Principal, s containerSession, step int, command string) (map[string]any, string, error) {
	ok, e := r.DB.RateLimit(ctx, "agentexec:"+p.User.ID, execBudget, time.Hour)
	if e != nil {
		return nil, "", e
	}
	if !ok {
		return nil, "", fmt.Errorf("agent command budget reached")
	}
	entry := map[string]any{"step": step, "command": security.Redact(command)}
	cmd, e := adapters.ExecCommand(s.Resource, command)
	if e != nil {
		entry["status"] = "rejected"
		entry["output"] = e.Error()
		return entry, commandResult(command, "rejected by the backend", e.Error()), nil
	}
	started := time.Now()
	out, runErr := r.Exec.Run(ctx, s.Host, cmd)
	status, ran := runStatus(runErr)
	seconds := int(time.Since(started).Seconds())
	event := domain.Event{Actor: p.User.ID, ActorType: "agent", HostID: s.Host.ID, ResourceID: s.Resource.ID, Environment: s.Host.Environment, Action: "agent.exec", Decision: "allow", Result: status, Metadata: map[string]any{"session": s.ID, "step": step, "container": s.Container, "command": security.Redact(command), "provider_id": s.ProviderID, "truncated": out.Truncated, "seconds": seconds}}
	if !ran {
		event.Result = runErr.Error()
		_ = r.DB.Audit(context.WithoutCancel(ctx), event)
		return nil, "", fmt.Errorf("command execution failed: %v", runErr)
	}
	output := security.Bounded(security.Redact(out.Output), execOutput, execOutputLines)
	entry["status"] = status
	entry["output"] = output
	entry["seconds"] = seconds
	if e = r.DB.Audit(ctx, event); e != nil {
		return nil, "", e
	}
	return entry, commandResult(command, status, output), nil
}
