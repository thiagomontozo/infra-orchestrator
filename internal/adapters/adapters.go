package adapters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"go.opentelemetry.io/otel"
	"strconv"
	"strings"
	"time"
)

type LogRequest struct {
	Host     domain.Host
	Resource domain.Resource
	Tail     int
	Since    string
}
type Adapter interface {
	Name() string
	Detect(context.Context, domain.Host) (bool, error)
	Discover(context.Context, domain.Host) ([]domain.Resource, error)
	Capabilities(domain.Resource) []string
	Execute(context.Context, domain.Host, domain.Resource, domain.Operation) (executor.Result, error)
	Logs(context.Context, LogRequest) (executor.Result, error)
}
type CLI struct {
	Provider string
	Executor executor.Executor
}
type Registry map[string]Adapter

func New(e executor.Executor) Registry {
	r := Registry{}
	for _, p := range []string{"docker", "dockercompose", "systemd", "podman", "podmancompose", "kubernetes", "nomad", "swarm", "supervisor", "pm2"} {
		r[p] = &CLI{p, e}
	}
	return r
}
func (a *CLI) Name() string { return a.Provider }
func (a *CLI) command(args ...string) executor.Command {
	program := a.Provider
	switch a.Provider {
	case "dockercompose":
		program = "docker"
		args = append([]string{"compose"}, args...)
	case "podmancompose":
		program = "podman-compose"
	case "systemd":
		program = "systemctl"
	case "kubernetes":
		program = "kubectl"
	case "swarm":
		program = "docker"
	case "supervisor":
		program = "supervisorctl"
	}
	return executor.Command{Program: program, Args: args}
}
func (a *CLI) Detect(ctx context.Context, h domain.Host) (bool, error) {
	args := []string{"--version"}
	switch a.Provider {
	case "docker", "podman":
		args = []string{"info", "--format", "json"}
	case "dockercompose":
		args = []string{"version", "--short"}
	case "kubernetes":
		args = []string{"version", "--client", "-o", "json"}
	case "nomad":
		args = []string{"version"}
	case "supervisor":
		args = []string{"version"}
	case "swarm":
		args = []string{"info", "--format", "{{.Swarm.LocalNodeState}}"}
	}
	out, e := a.Executor.Run(ctx, h, a.command(args...))
	if e != nil {
		return false, e
	}
	if a.Provider == "swarm" {
		return strings.TrimSpace(out.Output) == "active", nil
	}
	return true, nil
}
func (a *CLI) Discover(ctx context.Context, h domain.Host) ([]domain.Resource, error) {
	ctx, span := otel.Tracer("adapters").Start(ctx, a.Provider+".discover")
	defer span.End()
	var args []string
	switch a.Provider {
	case "docker", "podman":
		args = []string{"ps", "-a", "--no-trunc", "--format", "{{json .}}"}
	case "dockercompose":
		args = []string{"ls", "--all", "--format", "json"}
	case "podmancompose":
		args = []string{"--version"}
	case "systemd":
		args = []string{"list-units", "--type=service", "--all", "--no-pager", "--output=json"}
	case "kubernetes":
		args = []string{"get", "namespaces,nodes,deployments,statefulsets,daemonsets,pods,services,jobs,cronjobs", "--all-namespaces", "-o", "json"}
	case "nomad":
		args = []string{"job", "status", "-json"}
	case "swarm":
		args = []string{"service", "ls", "--format", "{{json .}}"}
	case "supervisor":
		args = []string{"status"}
	case "pm2":
		args = []string{"jlist"}
	default:
		return nil, fmt.Errorf("unknown adapter")
	}
	if a.Provider == "podmancompose" {
		pod := &CLI{Provider: "podman", Executor: a.Executor}
		resources, e := pod.Discover(ctx, h)
		if e != nil {
			return nil, e
		}
		projects := map[string]domain.Resource{}
		for _, r := range resources {
			if project := r.Labels["io.podman.compose.project"]; project != "" {
				projects[project] = domain.Resource{ExternalID: project, Name: project, Type: "podman_compose_project", State: r.State, Metadata: map[string]any{}}
			}
		}
		out := []domain.Resource{}
		for _, r := range projects {
			r.Capabilities = a.Capabilities(r)
			r.Environment = h.Environment
			out = append(out, r)
		}
		return out, nil
	}
	out, e := a.Executor.Run(ctx, h, a.command(args...))
	if e != nil {
		return nil, fmt.Errorf("%s discovery failed: %w", a.Provider, e)
	}
	if out.Truncated {
		return nil, fmt.Errorf("discovery output exceeded 1 MiB")
	}
	resources, e := Parse(a.Provider, []byte(out.Output))
	if e != nil {
		return nil, e
	}
	for i := range resources {
		resources[i].Provider = a.Provider
		resources[i].Environment = h.Environment
		resources[i].HostID = h.ID
		resources[i].Capabilities = a.Capabilities(resources[i])
	}
	return resources, nil
}
func (a *CLI) Capabilities(r domain.Resource) []string {
	switch a.Provider {
	case "docker", "podman":
		return []string{"inspect", "logs", "stats", "start", "stop", "restart", "pause", "unpause"}
	case "dockercompose", "podmancompose":
		return []string{"logs", "up", "down", "start", "stop", "restart", "recreate"}
	case "systemd":
		return []string{"status", "logs", "start", "stop", "restart", "reload"}
	case "kubernetes":
		switch r.Type {
		case "kubernetes_deployment", "kubernetes_statefulset":
			return []string{"describe", "events", "logs", "restart", "scale", "rollout_status", "rollout_history", "rollback", "deploy"}
		case "kubernetes_daemonset":
			return []string{"describe", "events", "restart", "rollout_status", "rollout_history", "rollback"}
		case "kubernetes_pod":
			return []string{"describe", "events", "logs", "delete"}
		case "kubernetes_job", "kubernetes_cronjob":
			return []string{"describe", "events", "status"}
		default:
			return []string{"describe", "events"}
		}
	case "nomad":
		if r.Type == "nomad_allocation" {
			return []string{"status", "logs", "restart"}
		}
		return []string{"status", "run", "stop"}
	case "swarm":
		return []string{"inspect", "logs", "scale", "restart"}
	case "supervisor":
		return []string{"status", "logs", "start", "stop", "restart"}
	case "pm2":
		return []string{"status", "logs", "start", "stop", "restart", "reload"}
	}
	return nil
}
func (a *CLI) Execute(ctx context.Context, h domain.Host, r domain.Resource, o domain.Operation) (executor.Result, error) {
	ctx, span := otel.Tracer("adapters").Start(ctx, a.Provider+"."+o.Action)
	defer span.End()
	cmd, e := a.Build(r, o.Action, o.Parameters)
	if e != nil {
		return executor.Result{}, e
	}
	out, e := a.Executor.Run(ctx, h, cmd)
	out.Output = security.Redact(out.Output)
	return out, e
}
func (a *CLI) Logs(ctx context.Context, req LogRequest) (executor.Result, error) {
	return a.Execute(ctx, req.Host, req.Resource, domain.Operation{Action: "logs", Parameters: map[string]any{"tail": float64(req.Tail), "since": req.Since}})
}
func allowedParams(p map[string]any, keys ...string) error {
	for k := range p {
		if !domain.Contains(keys, k) {
			return fmt.Errorf("parameter %s is not allowed", k)
		}
	}
	return nil
}
func integer(p map[string]any, key string, def, min, max int) (int, error) {
	v, ok := p[key]
	if !ok {
		return def, nil
	}
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) || int(f) < min || int(f) > max {
		return 0, fmt.Errorf("%s must be %d..%d", key, min, max)
	}
	return int(f), nil
}
func (a *CLI) Build(r domain.Resource, action string, p map[string]any) (executor.Command, error) {
	var empty executor.Command
	if !domain.Contains(a.Capabilities(r), action) {
		return empty, fmt.Errorf("unsupported capability")
	}
	id := r.ExternalID
	if a.Provider == "kubernetes" {
		id = r.Name
	}
	if !executor.ValidRef(id) {
		return empty, fmt.Errorf("invalid resource identifier")
	}
	if e := allowedParams(p, "tail", "since", "replicas", "revision", "manifest", "version", "artifact", "commit"); e != nil {
		return empty, e
	}
	tail, e := integer(p, "tail", 200, 1, 2000)
	if e != nil {
		return empty, e
	}
	replicas, e := integer(p, "replicas", 1, 0, 1000)
	if e != nil {
		return empty, e
	}
	rev, e := integer(p, "revision", 0, 0, 1000000)
	if e != nil {
		return empty, e
	}
	since := domain.String(p, "since")
	if since != "" {
		if _, e := time.ParseDuration(since); e != nil {
			if _, e = time.Parse(time.RFC3339, since); e != nil {
				return empty, fmt.Errorf("invalid log time range")
			}
		}
	}
	var args []string
	switch a.Provider {
	case "docker", "podman":
		switch action {
		case "logs":
			args = []string{"logs", "--timestamps", "--tail", strconv.Itoa(tail)}
			if since != "" {
				args = append(args, "--since", since)
			}
			args = append(args, id)
		case "stats":
			args = []string{"stats", "--no-stream", "--format", "{{json .}}", id}
		case "inspect":
			args = []string{"inspect", id}
		default:
			args = []string{action, id}
		}
	case "dockercompose", "podmancompose":
		args = []string{"--project-name", id}
		if files := domain.String(r.Metadata, "config_files"); files != "" {
			for _, path := range strings.Split(files, ",") {
				if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "\r\n\x00") {
					return empty, fmt.Errorf("invalid compose file path")
				}
				args = append(args, "--file", path)
			}
		}
		switch action {
		case "up":
			args = append(args, "up", "-d")
		case "recreate":
			args = append(args, "up", "-d", "--force-recreate")
		case "logs":
			args = append(args, "logs", "--no-color", "--timestamps", "--tail", strconv.Itoa(tail))
		default:
			args = append(args, action)
		}
	case "systemd":
		if action == "logs" {
			args = []string{"--unit", id, "--no-pager", "--output=short-iso", "--lines", strconv.Itoa(tail)}
			return executor.Command{Program: "journalctl", Args: args}, nil
		}
		if action == "status" {
			args = []string{"show", id, "--property=Id,Description,LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestamp,NRestarts"}
		} else {
			args = []string{action, id, "--no-ask-password"}
		}
	case "kubernetes":
		if r.Namespace != "" && !executor.ValidRef(r.Namespace) {
			return empty, fmt.Errorf("invalid namespace")
		}
		kind := strings.TrimPrefix(r.Type, "kubernetes_")
		target := kind + "/" + r.Name
		args = []string{}
		if r.Namespace != "" {
			args = append(args, "--namespace", r.Namespace)
		}
		switch action {
		case "logs":
			args = append(args, "logs", target, "--timestamps", "--tail", strconv.Itoa(tail), "--all-containers=true")
		case "describe":
			args = append(args, "describe", target)
		case "events":
			args = append(args, "get", "events", "--field-selector", "involvedObject.name="+r.Name, "-o", "json")
		case "status":
			args = append(args, "get", target, "-o", "json")
		case "restart":
			args = append(args, "rollout", "restart", target)
		case "scale":
			args = append(args, "scale", target, "--replicas", strconv.Itoa(replicas))
		case "delete":
			args = append(args, "delete", target, "--wait=false")
		case "rollout_status":
			args = append(args, "rollout", "status", target, "--timeout=60s")
		case "rollout_history":
			args = append(args, "rollout", "history", target)
		case "rollback":
			args = append(args, "rollout", "undo", target)
			if rev > 0 {
				args = append(args, "--to-revision", strconv.Itoa(rev))
			}
		case "deploy":
			manifest := domain.String(p, "manifest")
			if e := ValidateManifest("kubernetes", r, manifest); e != nil {
				return empty, e
			}
			cmd := a.command(append(args, "apply", "-f", "-")...)
			cmd.Stdin = []byte(manifest)
			return cmd, nil
		}
	case "nomad":
		switch action {
		case "status":
			if r.Type == "nomad_allocation" {
				args = []string{"alloc", "status", "-json", id}
			} else {
				args = []string{"job", "status", "-json", id}
			}
		case "stop":
			args = []string{"job", "stop", id}
		case "restart":
			args = []string{"alloc", "restart", id}
		case "logs":
			args = []string{"alloc", "logs", "-tail", "-n", strconv.Itoa(tail), id}
		case "run":
			manifest := domain.String(p, "manifest")
			if e := ValidateManifest("nomad", r, manifest); e != nil {
				return empty, e
			}
			cmd := a.command("job", "run", "-json", "-")
			cmd.Stdin = []byte(manifest)
			return cmd, nil
		}
	case "swarm":
		switch action {
		case "inspect":
			args = []string{"service", "inspect", id}
		case "logs":
			args = []string{"service", "logs", "--timestamps", "--tail", strconv.Itoa(tail), id}
		case "scale":
			args = []string{"service", "scale", id + "=" + strconv.Itoa(replicas)}
		case "restart":
			args = []string{"service", "update", "--force", id}
		}
	case "supervisor":
		if action == "logs" {
			args = []string{"tail", "-" + strconv.Itoa(min(tail*200, 65536)), id, "stdout"}
		} else {
			args = []string{action, id}
		}
	case "pm2":
		switch action {
		case "logs":
			args = []string{"logs", id, "--nostream", "--lines", strconv.Itoa(tail)}
		case "status":
			args = []string{"describe", id}
		default:
			args = []string{action, id}
		}
	default:
		return empty, fmt.Errorf("adapter unavailable")
	}
	return a.command(args...), nil
}
func ValidateManifest(provider string, r domain.Resource, manifest string) error {
	if len(manifest) == 0 || len(manifest) > 256*1024 {
		return fmt.Errorf("JSON manifest required, at most 256 KiB")
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(manifest))
	if e := dec.Decode(&m); e != nil {
		return fmt.Errorf("valid JSON manifest required")
	}
	if !json.Valid([]byte(manifest)) {
		return fmt.Errorf("invalid manifest")
	}
	if provider == "kubernetes" {
		meta, _ := m["metadata"].(map[string]any)
		kind := strings.ToLower(domain.String(m, "kind"))
		if domain.String(meta, "name") != r.Name || domain.String(meta, "namespace") != r.Namespace || "kubernetes_"+kind != r.Type {
			return fmt.Errorf("manifest must target exactly this workload and namespace")
		}
		if !domain.Contains([]string{"deployment", "statefulset"}, kind) {
			return fmt.Errorf("unsupported manifest kind")
		}
	} else {
		job, _ := m["Job"].(map[string]any)
		if job == nil {
			job = m
		}
		if domain.String(job, "ID") != r.ExternalID {
			return fmt.Errorf("manifest job ID must match resource")
		}
	}
	return nil
}
func decodeRows(b []byte) ([]map[string]any, error) {
	var rows []map[string]any
	if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		e := json.Unmarshal(b, &rows)
		return rows, e
	}
	s := bufio.NewScanner(strings.NewReader(string(b)))
	s.Buffer(make([]byte, 4096), 1024*1024)
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var row map[string]any
		if e := json.Unmarshal(s.Bytes(), &row); e != nil {
			return nil, e
		}
		rows = append(rows, row)
	}
	return rows, s.Err()
}
