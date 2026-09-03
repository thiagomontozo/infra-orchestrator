package adapters

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"testing"
)

func TestKubeconfigRejectsExecutableAndInsecure(t *testing.T) {
	for _, raw := range []string{`{"current-context":"c","users":[{"name":"u","user":{"exec":{"command":"bash"}}}]}`, `{"current-context":"c","clusters":[{"name":"c","cluster":{"server":"https://cluster","insecure-skip-tls-verify":true}}]}`, `{"current-context":"c","clusters":[{"name":"c","cluster":{"server":"https://cluster","certificate-authority":"/etc/passwd"}}]}`} {
		if _, e := ParseKubeconfig([]byte(raw)); e == nil {
			t.Fatal("unsafe kubeconfig accepted")
		}
	}
}
func TestKubeResourcePaths(t *testing.T) {
	p, e := kubePath(domain.Resource{Type: "kubernetes_deployment", Name: "api", Namespace: "staging"})
	if e != nil || p != "/apis/apps/v1/namespaces/staging/deployments/api" {
		t.Fatal(p, e)
	}
	if _, e = kubePath(domain.Resource{Type: "kubernetes_pod", Name: "../../secrets", Namespace: "default"}); e == nil {
		t.Fatal("path traversal accepted")
	}
}
