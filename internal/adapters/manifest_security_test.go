package adapters

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"testing"
)

func TestManifestRejectsHostEscape(t *testing.T) {
	for _, input := range []any{
		map[string]any{"securityContext": map[string]any{"privileged": true}},
		map[string]any{"volumes": []any{map[string]any{"hostPath": map[string]any{"path": "/"}}}},
		map[string]any{"volumes": []any{"/var/run/docker.sock:/var/run/docker.sock"}},
		map[string]any{"Driver": "raw_exec"},
		map[string]any{"hostNetwork": true},
	} {
		if validateWorkload(input) == nil {
			t.Fatalf("host access accepted: %#v", input)
		}
	}
	if e := validateWorkload(map[string]any{"image": "nginx:alpine", "volumes": []any{"data:/data"}}); e != nil {
		t.Fatal(e)
	}
}
func TestSwarmDeployTargetAndStdin(t *testing.T) {
	a := CLI{Provider: "swarm"}
	r := domain.Resource{Type: "docker_swarm_stack", Name: "web", ExternalID: "docker_swarm_stack/web"}
	manifest := `{"services":{"api":{"image":"nginx:alpine"}}}`
	c, e := a.Build(r, "deploy", map[string]any{"manifest": manifest})
	if e != nil {
		t.Fatal(e)
	}
	if c.Program != "docker" || string(c.Stdin) != manifest || c.Args[len(c.Args)-1] != "web" {
		t.Fatal(c)
	}
}
