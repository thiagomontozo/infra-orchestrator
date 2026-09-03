package rbac

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"testing"
)

func TestScopeAndRole(t *testing.T) {
	p := domain.Principal{User: domain.User{Role: "VIEWER", Enabled: true, Environments: []string{"staging"}}}
	if Allowed(p, "container.restart", "staging") || Allowed(p, "resource.read", "production") {
		t.Fatal("privilege escalation")
	}
	if !Allowed(p, "resource.read", "staging") {
		t.Fatal("read denied")
	}
	p.User.Role = "ADMIN"
	p.TokenID = "token"
	p.Scopes = []string{"resource.read"}
	if Allowed(p, "user.manage", "") {
		t.Fatal("API token scope bypass")
	}
	p.User.Enabled = false
	if Allowed(p, "resource.read", "") {
		t.Fatal("disabled user allowed")
	}
}
