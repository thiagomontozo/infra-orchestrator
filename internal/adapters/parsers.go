package adapters

import (
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"strconv"
	"strings"
)

func text(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
		if n, ok := m[k].(float64); ok {
			return strconv.FormatFloat(n, 'f', -1, 64)
		}
		if arr, ok := m[k].([]any); ok && len(arr) > 0 {
			if s, ok := arr[0].(string); ok {
				return s
			}
		}
	}
	return ""
}
func object(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}
func labels(v any) map[string]string {
	out := map[string]string{}
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	case string:
		for _, pair := range strings.Split(x, ",") {
			if k, v, ok := strings.Cut(pair, "="); ok {
				out[k] = v
			}
		}
	}
	return out
}
func Parse(provider string, b []byte) ([]domain.Resource, error) {
	out := []domain.Resource{}
	if provider == "supervisor" {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			state := strings.ToLower(f[1])
			out = append(out, domain.Resource{ExternalID: f[0], Name: f[0], Type: "supervisor_process", State: state, Health: health(state), Metadata: map[string]any{"description": strings.Join(f[2:], " ")}})
		}
		return out, nil
	}
	if provider == "kubernetes" {
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if e := json.Unmarshal(b, &list); e != nil {
			return nil, e
		}
		for _, m := range list.Items {
			meta, status, spec := object(m, "metadata"), object(m, "status"), object(m, "spec")
			kind := strings.ToLower(text(m, "kind"))
			name, ns := text(meta, "name"), text(meta, "namespace")
			state := text(status, "phase")
			h := "unknown"
			if kind == "pod" {
				statuses, _ := status["containerStatuses"].([]any)
				healthy := len(statuses) > 0
				for _, v := range statuses {
					c, _ := v.(map[string]any)
					healthy = healthy && domain.Bool(c, "ready")
					waiting := object(object(c, "state"), "waiting")
					if reason := text(waiting, "reason"); reason != "" {
						state = reason
					}
				}
				if healthy {
					h = "healthy"
				} else {
					h = "unhealthy"
				}
			} else if kind == "deployment" || kind == "statefulset" || kind == "daemonset" {
				desired := domain.Number(spec, "replicas")
				if kind == "daemonset" {
					desired = domain.Number(status, "desiredNumberScheduled")
				}
				ready := domain.Number(status, "readyReplicas")
				if kind == "daemonset" {
					ready = domain.Number(status, "numberReady")
				}
				state = fmt.Sprintf("%g/%g ready", ready, desired)
				if ready >= desired {
					h = "healthy"
				} else {
					h = "unhealthy"
				}
			}
			out = append(out, domain.Resource{ExternalID: kind + "/" + ns + "/" + name, Name: name, Namespace: ns, Type: "kubernetes_" + kind, State: state, Health: h, Labels: labels(meta["labels"]), Metadata: map[string]any{"status": status, "uid": meta["uid"], "generation": meta["generation"]}})
		}
		return out, nil
	}
	rows, e := decodeRows(b)
	if e != nil {
		return nil, fmt.Errorf("%s parser: %w", provider, e)
	}
	for _, m := range rows {
		r := domain.Resource{Labels: map[string]string{}, Metadata: map[string]any{}}
		switch provider {
		case "docker", "podman":
			r.ExternalID = text(m, "ID", "Id", "id")
			r.Name = text(m, "Names", "Name", "names")
			r.Type = provider + "_container"
			r.State = strings.ToLower(text(m, "State", "Status", "state", "status"))
			r.Labels = labels(m["Labels"])
			r.Metadata = map[string]any{"image": text(m, "Image", "ImageName"), "ports": m["Ports"], "networks": m["Networks"], "status": text(m, "Status"), "created_at": m["CreatedAt"]}
		case "dockercompose":
			r.Name = text(m, "Name")
			r.ExternalID = r.Name
			r.Type = "docker_compose_project"
			r.State = text(m, "Status")
			r.Metadata["config_files"] = text(m, "ConfigFiles")
		case "systemd":
			r.Name = text(m, "unit")
			r.ExternalID = r.Name
			r.Type = "systemd_service"
			r.State = text(m, "active")
			r.Metadata = map[string]any{"description": m["description"], "load_state": m["load"], "sub_state": m["sub"]}
		case "nomad":
			r.Name = text(m, "Name", "ID")
			r.ExternalID = text(m, "ID")
			r.Type = "nomad_job"
			r.Namespace = text(m, "Namespace")
			r.State = text(m, "Status")
			r.Metadata = map[string]any{"type": m["Type"], "summary": m["JobSummary"], "version": m["Version"]}
		case "swarm":
			r.Name = text(m, "Name")
			r.ExternalID = text(m, "ID")
			r.Type = "docker_swarm_service"
			r.State = text(m, "Replicas")
			r.Metadata = map[string]any{"replicas": m["Replicas"], "image": m["Image"], "mode": m["Mode"]}
		case "pm2":
			env := object(m, "pm2_env")
			r.Name = text(m, "name")
			r.ExternalID = text(m, "pm_id")
			r.Type = "pm2_process"
			r.State = text(env, "status")
			r.Metadata = map[string]any{"pid": m["pid"], "uptime": env["pm_uptime"], "restarts": env["restart_time"], "metrics": m["monit"]}
		default:
			return nil, fmt.Errorf("unsupported parser: %s", provider)
		}
		if r.ExternalID == "" {
			return nil, fmt.Errorf("missing %s resource ID", provider)
		}
		r.Health = health(r.State)
		out = append(out, r)
	}
	return out, nil
}
func health(s string) string {
	s = strings.ToLower(s)
	for _, v := range []string{"unhealthy", "failed", "fatal", "errored", "crashloop", "backoff"} {
		if strings.Contains(s, v) {
			return "unhealthy"
		}
	}
	for _, v := range []string{"running", "active", "online", "healthy", "up "} {
		if strings.Contains(s, v) {
			return "healthy"
		}
	}
	return "unknown"
}
