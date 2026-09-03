package provisioning

import (
	"testing"
)

func TestSpecSafeguards(t *testing.T) {
	s := Spec{Name: "api", Image: "ghcr.io/acme/api:v1", MemoryMB: 256, CPUs: 1, RestartPolicy: "unless-stopped"}
	if e := Validate(s); e != nil {
		t.Fatal(e)
	}
	s.Image = "nginx; rm -rf /"
	if Validate(s) == nil {
		t.Fatal("unsafe image")
	}
	s.Image = "nginx:alpine"
	s.Ports = []Port{{Container: 80, Host: 0, Protocol: "tcp", BindIP: "0.0.0.0"}}
	if Validate(s) == nil {
		t.Fatal("invalid mapping")
	}
}
