package provisioning

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/secrets"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type EngineAPI interface {
	DockerAPI(context.Context, domain.Host, string, string, []byte, string) ([]byte, error)
}
type Docker struct {
	API     EngineAPI
	DB      *store.DB
	Secrets secrets.Provider
	CLI     adapters.Adapter
}
type Port struct {
	Container int    `json:"container"`
	Host      int    `json:"host"`
	Protocol  string `json:"protocol"`
	BindIP    string `json:"bind_ip"`
}
type Spec struct {
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	RegistryID    string            `json:"registry_id"`
	Ports         []Port            `json:"ports"`
	Environment   map[string]string `json:"environment"`
	MemoryMB      int               `json:"memory_mb"`
	CPUs          float64           `json:"cpus"`
	RestartPolicy string            `json:"restart_policy"`
	ReadOnly      bool              `json:"read_only"`
	User          string            `json:"user"`
}

var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:-]*(?:@sha256:[a-f0-9]{64})?$`)
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Validate(spec Spec) error {
	if !namePattern.MatchString(spec.Name) || !imagePattern.MatchString(spec.Image) || len(spec.Image) > 512 {
		return fmt.Errorf("invalid container name or image reference")
	}
	if spec.MemoryMB < 16 || spec.MemoryMB > 262144 || spec.CPUs < 0.1 || spec.CPUs > 64 {
		return fmt.Errorf("memory must be 16..262144 MiB and CPUs 0.1..64")
	}
	if !domain.Contains([]string{"no", "always", "unless-stopped", "on-failure"}, spec.RestartPolicy) {
		return fmt.Errorf("invalid restart policy")
	}
	if len(spec.Ports) > 32 || len(spec.Environment) > 100 {
		return fmt.Errorf("too many ports or environment variables")
	}
	for _, p := range spec.Ports {
		if p.Container < 1 || p.Container > 65535 || p.Host < 1 || p.Host > 65535 || !domain.Contains([]string{"tcp", "udp"}, p.Protocol) || !domain.Contains([]string{"127.0.0.1", "0.0.0.0"}, p.BindIP) {
			return fmt.Errorf("invalid port mapping")
		}
	}
	for k, v := range spec.Environment {
		if !envPattern.MatchString(k) || len(v) > 8192 || strings.ContainsRune(v, 0) {
			return fmt.Errorf("invalid environment variable")
		}
	}
	if spec.User != "" && !regexp.MustCompile(`^[0-9]{1,10}(:[0-9]{1,10})?$`).MatchString(spec.User) {
		return fmt.Errorf("container user must be numeric UID[:GID]")
	}
	return nil
}
func (d *Docker) Name() string { return "provisioning" }
func (d *Docker) Detect(ctx context.Context, h domain.Host) (bool, error) {
	return d.CLI.Detect(ctx, h)
}
func (d *Docker) Discover(_ context.Context, h domain.Host) ([]domain.Resource, error) {
	return []domain.Resource{{ExternalID: "docker-engine", Name: "Docker provisioning", Provider: "provisioning", Type: "docker_engine", State: "available", Environment: h.Environment, Capabilities: []string{"create"}, Metadata: map[string]any{}}}, nil
}
func (d *Docker) Capabilities(_ domain.Resource) []string { return []string{"create"} }
func (d *Docker) Logs(context.Context, adapters.LogRequest) (executor.Result, error) {
	return executor.Result{}, fmt.Errorf("select the created container for logs")
}
func (d *Docker) Execute(ctx context.Context, h domain.Host, r domain.Resource, op domain.Operation) (executor.Result, error) {
	var out executor.Result
	if op.Action != "create" {
		return out, fmt.Errorf("unsupported provisioning action")
	}
	secretID := domain.String(op.Parameters, "spec_secret_id")
	b, e := d.Secrets.Get(ctx, secretID)
	if e != nil {
		return out, e
	}
	var spec Spec
	if security.HashToken(string(b)) != domain.String(op.Parameters, "spec_hash") {
		return out, fmt.Errorf("container specification integrity mismatch")
	}
	if e = json.Unmarshal(b, &spec); e != nil {
		return out, e
	}
	if e = Validate(spec); e != nil {
		return out, e
	}
	auth := ""
	if spec.RegistryID != "" {
		registry, e := d.DB.Object(ctx, "registries", spec.RegistryID)
		if e != nil {
			return out, e
		}
		if registry.Environment != "" && registry.Environment != h.Environment {
			return out, fmt.Errorf("registry environment mismatch")
		}
		server := domain.String(registry.Data, "server")
		host := strings.Split(spec.Image, "/")[0]
		if server == "docker.io" {
			if strings.Contains(host, ".") && host != "docker.io" {
				return out, fmt.Errorf("image registry does not match credentials")
			}
		} else if host != server {
			return out, fmt.Errorf("image registry does not match credentials")
		}
		key, e := d.Secrets.Get(ctx, domain.String(registry.Data, "secret_id"))
		if e != nil {
			return out, e
		}
		payload, _ := json.Marshal(map[string]string{"username": domain.String(registry.Data, "username"), "password": string(key), "serveraddress": server})
		auth = base64.URLEncoding.EncodeToString(payload)
	}
	b, e = d.API.DockerAPI(ctx, h, "POST", "/images/create?fromImage="+url.QueryEscape(spec.Image), nil, auth)
	if e != nil {
		return out, e
	}
	for _, line := range strings.Split(string(b), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && domain.String(m, "error") != "" {
			return out, fmt.Errorf("image pull failed: %s", domain.String(m, "error"))
		}
	}
	env := []string{}
	for k, v := range spec.Environment {
		env = append(env, k+"="+v)
	}
	exposed := map[string]any{}
	bindings := map[string]any{}
	for _, p := range spec.Ports {
		key := strconv.Itoa(p.Container) + "/" + p.Protocol
		exposed[key] = map[string]any{}
		bindings[key] = []map[string]string{{"HostIp": p.BindIP, "HostPort": strconv.Itoa(p.Host)}}
	}
	body := map[string]any{"Image": spec.Image, "Env": env, "User": spec.User, "Labels": map[string]string{"io.infra-orchestrator.managed": "true", "io.infra-orchestrator.operation": op.ID, "io.infra-orchestrator.environment": h.Environment}, "ExposedPorts": exposed, "HostConfig": map[string]any{"Memory": int64(spec.MemoryMB) * 1024 * 1024, "NanoCpus": int64(spec.CPUs * 1e9), "PidsLimit": 256, "ReadonlyRootfs": spec.ReadOnly, "Privileged": false, "CapDrop": []string{"ALL"}, "CapAdd": []string{"CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE"}, "SecurityOpt": []string{"no-new-privileges:true"}, "PortBindings": bindings, "RestartPolicy": map[string]string{"Name": spec.RestartPolicy}}}
	payload, _ := json.Marshal(body)
	b, e = d.API.DockerAPI(ctx, h, "POST", "/containers/create?name="+url.QueryEscape(spec.Name), payload, "")
	if e != nil {
		return out, e
	}
	var created struct {
		ID string `json:"Id"`
	}
	if e = json.Unmarshal(b, &created); e != nil || created.ID == "" {
		return out, fmt.Errorf("invalid container creation response")
	}
	out.Output = "Created container " + created.ID + " from " + spec.Image
	b, e = d.API.DockerAPI(ctx, h, "POST", "/containers/"+url.PathEscape(created.ID)+"/start", nil, "")
	if e != nil {
		return out, fmt.Errorf("container %s created but start failed: %w", created.ID, e)
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return out, ctx.Err()
	case <-timer.C:
	}
	b, e = d.API.DockerAPI(ctx, h, "GET", "/containers/"+url.PathEscape(created.ID)+"/json", nil, "")
	if e != nil {
		return out, e
	}
	var status struct {
		State struct {
			Running bool
			Error   string
		}
	}
	if e = json.Unmarshal(b, &status); e != nil {
		return out, e
	}
	if !status.State.Running {
		return out, fmt.Errorf("container %s exited after start; inspect its logs", created.ID)
	}
	out.Output += "\nContainer running; application readiness depends on its healthcheck."
	return out, nil
}
