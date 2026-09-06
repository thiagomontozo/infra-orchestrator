package adapters

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"strings"
	"testing"
)

func TestConsoleCommandOnlyAttachesToContainers(t *testing.T) {
	container := domain.Resource{Provider: "docker", Type: "docker_container", ExternalID: "abc123"}
	cmd, target, e := ConsoleCommand(container, "sh")
	if e != nil {
		t.Fatalf("docker container refused: %v", e)
	}
	if target.Container != "abc123" || target.Shell != "sh" || cmd.Program != "docker" {
		t.Fatalf("unexpected target %+v for %+v", target, cmd)
	}
	rendered, e := cmd.Render()
	if e != nil {
		t.Fatalf("command does not pass the binary allowlist: %v", e)
	}
	// Render quotes every argument, so the shape is: docker 'exec' '--tty' ...
	for _, want := range []string{"docker ", "'exec'", "'--interactive'", "'--tty'", "'abc123'", "'sh'"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered command missing %s: %s", want, rendered)
		}
	}

	service := domain.Resource{Provider: "dockercompose", Type: "docker_compose_service", ExternalID: "app/api", Metadata: map[string]any{"container": "339d361e351c"}}
	if _, target, e = ConsoleCommand(service, "bash"); e != nil {
		t.Fatalf("compose service refused: %v", e)
	}
	if target.Container != "339d361e351c" || target.Shell != "bash" {
		t.Fatalf("compose service must attach to metadata.container, got %+v", target)
	}

	if cmd, _, e = ConsoleCommand(domain.Resource{Provider: "podman", Type: "podman_container", ExternalID: "abc123"}, "sh"); e != nil || cmd.Program != "podman" {
		t.Fatalf("podman container must use podman, got %+v (%v)", cmd, e)
	}

	// Nothing with a single attachable container: there is no shell to open.
	for _, r := range []domain.Resource{
		{Provider: "dockercompose", Type: "docker_compose_project", ExternalID: "app"},
		{Provider: "kubernetes", Type: "kubernetes_deployment", ExternalID: "api"},
		{Provider: "systemd", Type: "systemd_service", ExternalID: "nginx.service"},
		{Provider: "docker", Type: "docker_container", ExternalID: ""},
		{Provider: "dockercompose", Type: "docker_compose_service", Metadata: map[string]any{}},
	} {
		if _, _, e = ConsoleCommand(r, "sh"); e == nil {
			t.Fatalf("resource without an attachable container accepted: %+v", r)
		}
	}

	for _, id := range []string{"abc;rm -rf /", "abc$(id)", "abc container", "-rf", "a..b", "abc\nwhoami"} {
		if _, _, e = ConsoleCommand(domain.Resource{Provider: "docker", Type: "docker_container", ExternalID: id}, "sh"); e == nil {
			t.Fatalf("container identifier accepted: %q", id)
		}
	}

	for _, shell := range []string{"zsh", "python", "bash -c id", "../bin/sh", "sh;id"} {
		if _, _, e = ConsoleCommand(container, shell); e == nil {
			t.Fatalf("shell outside the allowlist accepted: %q", shell)
		}
	}
}
