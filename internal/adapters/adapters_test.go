package adapters

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"strings"
	"testing"
)

func TestParsers(t *testing.T) {
	cases := []struct{ p, raw, typ string }{{"docker", `{"ID":"abc123","Names":"api","State":"running","Labels":"app=api"}`, "docker_container"}, {"podman", `[{"Id":"abc123","Names":["api"],"State":"running"}]`, "podman_container"}, {"dockercompose", `[{"Name":"app","Status":"running(2)","ConfigFiles":"/srv/app/compose.yml"}]`, "docker_compose_project"}, {"systemd", `[{"unit":"nginx.service","active":"failed","sub":"failed"}]`, "systemd_service"}, {"kubernetes", `{"items":[{"kind":"Deployment","metadata":{"name":"api","namespace":"default"},"spec":{"replicas":2},"status":{"readyReplicas":1}}]}`, "kubernetes_deployment"}, {"nomad", `[{"ID":"api","Name":"api","Status":"running"}]`, "nomad_job"}, {"swarm", `{"ID":"abc","Name":"api","Replicas":"1/1"}`, "docker_swarm_service"}, {"supervisor", "api RUNNING pid 12, uptime 1:00:00", "supervisor_process"}, {"pm2", `[{"pm_id":0,"name":"api","pm2_env":{"status":"online","env":{"SECRET":"private"}},"monit":{"cpu":1}}]`, "pm2_process"}}
	for _, c := range cases {
		t.Run(c.p, func(t *testing.T) {
			r, e := Parse(c.p, []byte(c.raw))
			if e != nil || len(r) != 1 || r[0].Type != c.typ {
				t.Fatalf("parse: %v %#v", e, r)
			}
		})
	}
}
func TestCommandsAndTampering(t *testing.T) {
	a := &CLI{Provider: "docker"}
	r := domain.Resource{ExternalID: "abc123"}
	cmd, e := a.Build(r, "restart", nil)
	if e != nil {
		t.Fatal(e)
	}
	s, _ := cmd.Render()
	if s != "docker 'restart' 'abc123'" {
		t.Fatal(s)
	}
	r.ExternalID = "--all"
	if _, e = a.Build(r, "restart", nil); e == nil {
		t.Fatal("argument injection")
	}
	r.ExternalID = "abc123"
	if _, e = a.Build(r, "restart", map[string]any{"command": "rm -rf /"}); e == nil {
		t.Fatal("arbitrary parameter")
	}
	a.Provider = "kubernetes"
	r = domain.Resource{Name: "api", ExternalID: "deployment/default/api", Type: "kubernetes_deployment", Namespace: "default"}
	cmd, e = a.Build(r, "scale", map[string]any{"replicas": float64(3)})
	if e != nil {
		t.Fatal(e)
	}
	s, _ = cmd.Render()
	if !strings.Contains(s, "'--replicas' '3'") {
		t.Fatal(s)
	}
	if _, e = a.Build(r, "scale", map[string]any{"replicas": -1.0}); e == nil {
		t.Fatal("negative replicas")
	}
}
func TestManifestScope(t *testing.T) {
	r := domain.Resource{Name: "api", Namespace: "staging", Type: "kubernetes_deployment"}
	if ValidateManifest("kubernetes", r, `{"kind":"Deployment","metadata":{"name":"api","namespace":"production"}}`) == nil {
		t.Fatal("cross namespace deployment allowed")
	}
}
