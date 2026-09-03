package operations

import (
	"context"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"testing"
)

func TestApprovalTargetBinding(t *testing.T) {
	e := Engine{}
	h := domain.Host{ID: "host", Hostname: "10.0.0.1", Port: 22, Fingerprint: "SHA256:one", SecretID: "secret-version-one"}
	r := domain.Resource{ExternalID: "container", Provider: "docker", Type: "docker_container"}
	original, err := e.TargetHash(context.Background(), h, r)
	if err != nil {
		t.Fatal(err)
	}
	h.State = "offline"
	same, _ := e.TargetHash(context.Background(), h, r)
	if same != original {
		t.Fatal("status should not invalidate identity")
	}
	h.Fingerprint = "SHA256:changed"
	changed, _ := e.TargetHash(context.Background(), h, r)
	if original == changed {
		t.Fatal("approval not bound to fingerprint")
	}
	h.Fingerprint = "SHA256:one"
	h.SecretID = "new-credential"
	changed, _ = e.TargetHash(context.Background(), h, r)
	if original == changed {
		t.Fatal("approval not bound to credential")
	}
}
