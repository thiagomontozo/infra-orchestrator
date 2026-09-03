package adapters

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/secrets"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"io"
	"net/http"
	"net/url"
	"sigs.k8s.io/yaml"
	"strings"
	"time"
)

type Kubeconfig struct {
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	Preferences    any    `json:"preferences"`
	CurrentContext string `json:"current-context"`
	Clusters       []struct {
		Name    string `json:"name"`
		Cluster struct {
			Server   string `json:"server"`
			CA       string `json:"certificate-authority-data"`
			CAFile   string `json:"certificate-authority"`
			Insecure bool   `json:"insecure-skip-tls-verify"`
		} `json:"cluster"`
	} `json:"clusters"`
	Users []struct {
		Name string `json:"name"`
		User struct {
			Token        string `json:"token"`
			Cert         string `json:"client-certificate-data"`
			Key          string `json:"client-key-data"`
			Exec         any    `json:"exec"`
			AuthProvider any    `json:"auth-provider"`
			TokenFile    string `json:"tokenFile"`
		} `json:"user"`
	} `json:"users"`
	Contexts []struct {
		Name    string `json:"name"`
		Context struct {
			Cluster   string `json:"cluster"`
			User      string `json:"user"`
			Namespace string `json:"namespace"`
		} `json:"context"`
	} `json:"contexts"`
}

func ParseKubeconfig(raw []byte) (Kubeconfig, error) {
	var cfg Kubeconfig
	if len(raw) > 256*1024 {
		return cfg, fmt.Errorf("kubeconfig exceeds 256 KiB")
	}
	if e := yaml.UnmarshalStrict(raw, &cfg); e != nil {
		return cfg, fmt.Errorf("invalid kubeconfig: %w", e)
	}
	if cfg.CurrentContext == "" {
		return cfg, fmt.Errorf("current-context required")
	}
	for _, c := range cfg.Clusters {
		if c.Cluster.Insecure || c.Cluster.CAFile != "" || !strings.HasPrefix(c.Cluster.Server, "https://") {
			return cfg, fmt.Errorf("HTTPS and embedded CA required; insecure TLS and local files are forbidden")
		}
	}
	for _, u := range cfg.Users {
		if u.User.Exec != nil || u.User.AuthProvider != nil || u.User.TokenFile != "" {
			return cfg, fmt.Errorf("exec/auth-provider plugins and token files are forbidden; use a scoped token or embedded certificate")
		}
	}
	return cfg, nil
}

type KubernetesAPI struct {
	DB      *store.DB
	Secrets secrets.Provider
	Network *security.NetworkPolicy
}
type kubeClient struct {
	server, token string
	client        *http.Client
}

func (k *KubernetesAPI) client(ctx context.Context, h domain.Host) (*kubeClient, error) {
	raw, e := k.Secrets.Get(ctx, h.SecretID)
	if e != nil {
		return nil, e
	}
	cfg, e := ParseKubeconfig(raw)
	if e != nil {
		return nil, e
	}
	cluster, user := "", ""
	for _, c := range cfg.Contexts {
		if c.Name == cfg.CurrentContext {
			cluster, user = c.Context.Cluster, c.Context.User
		}
	}
	if cluster == "" {
		return nil, fmt.Errorf("current context not found")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	server, token := "", ""
	for _, c := range cfg.Clusters {
		if c.Name == cluster {
			server = c.Cluster.Server
			if c.Cluster.CA != "" {
				ca, e := base64.StdEncoding.DecodeString(c.Cluster.CA)
				if e != nil {
					return nil, e
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(ca) {
					return nil, fmt.Errorf("invalid cluster CA")
				}
				tlsConfig.RootCAs = pool
			}
		}
	}
	for _, u := range cfg.Users {
		if u.Name == user {
			token = u.User.Token
			if u.User.Cert != "" {
				cert, e := base64.StdEncoding.DecodeString(u.User.Cert)
				if e != nil {
					return nil, e
				}
				key, e := base64.StdEncoding.DecodeString(u.User.Key)
				if e != nil {
					return nil, e
				}
				pair, e := tls.X509KeyPair(cert, key)
				if e != nil {
					return nil, e
				}
				tlsConfig.Certificates = []tls.Certificate{pair}
			}
		}
	}
	if token == "" && len(tlsConfig.Certificates) == 0 {
		return nil, fmt.Errorf("cluster credential required")
	}
	if e = k.Network.ValidateURL(server); e != nil {
		return nil, e
	}
	client := k.Network.Client(60 * time.Second)
	client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	return &kubeClient{server: strings.TrimRight(server, "/"), token: token, client: client}, nil
}
func (c *kubeClient) request(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, method, c.server+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, e := c.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
	if e != nil {
		return nil, e
	}
	if len(b) > 4*1024*1024 {
		return nil, fmt.Errorf("cluster response exceeds 4 MiB")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("Kubernetes HTTP %d: %s", res.StatusCode, security.Bounded(security.Redact(string(b)), 1000, 10))
	}
	return b, nil
}

var kubePaths = map[string]string{"namespace": "/api/v1/namespaces", "node": "/api/v1/nodes", "pod": "/api/v1/pods", "service": "/api/v1/services", "deployment": "/apis/apps/v1/deployments", "statefulset": "/apis/apps/v1/statefulsets", "daemonset": "/apis/apps/v1/daemonsets", "job": "/apis/batch/v1/jobs", "cronjob": "/apis/batch/v1/cronjobs"}

func kubePath(r domain.Resource) (string, error) {
	kind := strings.TrimPrefix(r.Type, "kubernetes_")
	path, ok := kubePaths[kind]
	if !ok || !executor.ValidRef(r.Name) {
		return "", fmt.Errorf("invalid Kubernetes resource")
	}
	if r.Namespace != "" {
		if !executor.ValidRef(r.Namespace) {
			return "", fmt.Errorf("invalid namespace")
		}
		i := strings.LastIndex(path, "/")
		path = path[:i] + "/namespaces/" + url.PathEscape(r.Namespace) + path[i:]
	}
	return path + "/" + url.PathEscape(r.Name), nil
}
func (k *KubernetesAPI) Name() string { return "kubernetes-api" }
func (k *KubernetesAPI) Detect(ctx context.Context, h domain.Host) (bool, error) {
	c, e := k.client(ctx, h)
	if e != nil {
		return false, e
	}
	_, e = c.request(ctx, "GET", "/version", "", nil)
	return e == nil, e
}
func (k *KubernetesAPI) Capabilities(r domain.Resource) []string {
	caps := (&CLI{Provider: "kubernetes"}).Capabilities(r)
	out := []string{}
	for _, c := range caps {
		if c == "rollback" && !domain.Bool(r.Metadata, "rollback_available") {
			continue
		}
		if c == "logs" && r.Type != "kubernetes_pod" {
			continue
		}
		if c == "rollout_status" || c == "rollout_history" {
			continue
		}
		out = append(out, c)
	}
	return out
}
func (k *KubernetesAPI) Discover(ctx context.Context, h domain.Host) ([]domain.Resource, error) {
	c, e := k.client(ctx, h)
	if e != nil {
		return nil, e
	}
	items := []any{}
	for _, path := range kubePaths {
		b, e := c.request(ctx, "GET", path+"?limit=500", "", nil)
		if e != nil {
			return nil, e
		}
		var list struct {
			Items    []any `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if e = json.Unmarshal(b, &list); e != nil {
			return nil, e
		}
		items = append(items, list.Items...)
		for list.Metadata.Continue != "" {
			b, e = c.request(ctx, "GET", path+"?limit=500&continue="+url.QueryEscape(list.Metadata.Continue), "", nil)
			if e != nil {
				return nil, e
			}
			list.Items = nil
			list.Metadata.Continue = ""
			if e = json.Unmarshal(b, &list); e != nil {
				return nil, e
			}
			items = append(items, list.Items...)
			if len(items) > 10000 {
				return nil, fmt.Errorf("cluster inventory exceeds 10000 resources")
			}
		}
	}
	b, _ := json.Marshal(map[string]any{"items": items})
	resources, e := Parse("kubernetes", b)
	if e != nil {
		return nil, e
	}
	snapshots, e := k.DB.Objects(ctx, "snapshots")
	if e != nil {
		return nil, e
	}
	available := map[string]bool{}
	for _, snapshot := range snapshots {
		available[domain.String(snapshot.Data, "resource_id")] = true
	}
	for i := range resources {
		resources[i].Provider = k.Name()
		resources[i].HostID = h.ID
		resources[i].Environment = h.Environment
		if resources[i].Metadata == nil {
			resources[i].Metadata = map[string]any{}
		}
		id := security.HashToken(h.ID + "/" + k.Name() + "/" + resources[i].ExternalID)[:32]
		resources[i].Metadata["rollback_available"] = available[id]
		resources[i].Capabilities = k.Capabilities(resources[i])
	}
	return resources, e
}
func (k *KubernetesAPI) Logs(ctx context.Context, req LogRequest) (executor.Result, error) {
	return k.Execute(ctx, req.Host, req.Resource, domain.Operation{Action: "logs", Parameters: map[string]any{"tail": float64(req.Tail)}})
}
func (k *KubernetesAPI) Execute(ctx context.Context, h domain.Host, r domain.Resource, op domain.Operation) (executor.Result, error) {
	var out executor.Result
	if !domain.Contains(k.Capabilities(r), op.Action) {
		return out, fmt.Errorf("unsupported capability")
	}
	path, e := kubePath(r)
	if e != nil {
		return out, e
	}
	c, e := k.client(ctx, h)
	if e != nil {
		return out, e
	}
	method, contentType := "GET", ""
	var body []byte
	switch op.Action {
	case "logs":
		tail, e := integer(op.Parameters, "tail", 200, 1, 2000)
		if e != nil {
			return out, e
		}
		path += "/log?timestamps=true&tailLines=" + fmt.Sprint(tail)
	case "events":
		path = "/api/v1/namespaces/" + url.PathEscape(r.Namespace) + "/events?fieldSelector=" + url.QueryEscape("involvedObject.name="+r.Name)
	case "describe", "status":
	case "delete":
		method = "DELETE"
		contentType = "application/json"
		body = []byte(`{"kind":"DeleteOptions","apiVersion":"v1","gracePeriodSeconds":30}`)
	case "scale":
		replicas, e := integer(op.Parameters, "replicas", 1, 0, 1000)
		if e != nil {
			return out, e
		}
		path += "/scale"
		method = "PATCH"
		contentType = "application/merge-patch+json"
		body, _ = json.Marshal(map[string]any{"spec": map[string]any{"replicas": replicas}})
	case "restart", "deploy", "rollback":
		previous, e := c.request(ctx, "GET", path, "", nil)
		if e != nil {
			return out, e
		}
		if op.Action == "rollback" {
			if domain.Number(op.Parameters, "revision") != 0 {
				return out, fmt.Errorf("native snapshot rollback supports revision 0 only")
			}
			snapshots, e := k.DB.Objects(ctx, "snapshots")
			if e != nil {
				return out, e
			}
			var sid string
			for _, s := range snapshots {
				if domain.String(s.Data, "resource_id") == r.ID {
					sid = domain.String(s.Data, "manifest_secret_id")
					break
				}
			}
			if sid == "" {
				return out, fmt.Errorf("no stored snapshot; rollback unavailable")
			}
			old, e := k.Secrets.Get(ctx, sid)
			if e != nil {
				return out, e
			}
			var m map[string]any
			if e = json.Unmarshal(old, &m); e != nil {
				return out, e
			}
			body, _ = json.Marshal(map[string]any{"spec": m["spec"]})
			method = "PATCH"
			contentType = "application/merge-patch+json"
		} else if op.Action == "restart" {
			method = "PATCH"
			contentType = "application/strategic-merge-patch+json"
			body, _ = json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]string{"infra-orchestrator/restartedAt": time.Now().UTC().Format(time.RFC3339)}}}}})
		} else {
			manifest := domain.String(op.Parameters, "manifest")
			if e = ValidateManifest("kubernetes", r, manifest); e != nil {
				return out, e
			}
			method = "PATCH"
			path += "?fieldManager=infra-orchestrator"
			contentType = "application/apply-patch+yaml"
			body = []byte(manifest)
		}
		snapshotID := domain.ID()
		if e = k.Secrets.Put(ctx, snapshotID, previous); e != nil {
			return out, e
		}
		if e = k.DB.SaveObject(ctx, domain.Object{ID: domain.ID(), Kind: "snapshots", Name: op.ID, Environment: h.Environment, Data: map[string]any{"resource_id": r.ID, "operation_id": op.ID, "manifest_secret_id": snapshotID}}); e != nil {
			return out, e
		}
	default:
		return out, fmt.Errorf("action not implemented")
	}
	b, e := c.request(ctx, method, path, contentType, body)
	out.Output = security.Bounded(security.SanitizeText(string(b)), 65536, 2000)
	return out, e
}
