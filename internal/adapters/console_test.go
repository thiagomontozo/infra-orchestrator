package adapters

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"strings"
	"testing"
)

func TestConsoleCommandOnlyAttachesToContainers(t *testing.T) {
	container := domain.Resource{Provider: "docker", Type: "docker_container", ExternalID: "abc123"}
	cmd, e := ConsoleCommand(container, "")
	if e != nil || cmd.Program != "docker" || strings.Join(cmd.Args, " ") != "exec --interactive --tty abc123 sh" {
		t.Fatalf("container console built wrong: %v %v", cmd, e)
	}
	if _, e = cmd.Render(); e != nil {
		t.Fatalf("console command rejected by the executable allowlist: %v", e)
	}
	service := domain.Resource{Provider: "dockercompose", Type: "docker_compose_service", ExternalID: "app/api", Metadata: map[string]any{"container": "c8597c5a76a6"}}
	cmd, e = ConsoleCommand(service, "bash")
	if e != nil || strings.Join(cmd.Args, " ") != "exec --interactive --tty c8597c5a76a6 bash" {
		t.Fatalf("compose service console built wrong: %v %v", cmd, e)
	}
	for _, r := range []domain.Resource{
		{Provider: "dockercompose", Type: "docker_compose_project", ExternalID: "app"},
		{Provider: "kubernetes", Type: "kubernetes_deployment", ExternalID: "api"},
		{Provider: "systemd", Type: "systemd_service", ExternalID: "nginx.service"},
		{Provider: "docker", Type: "docker_container", ExternalID: "abc;rm -rf /"},
		{Provider: "dockercompose", Type: "docker_compose_service", ExternalID: "app/api"},
	} {
		if _, e = ConsoleCommand(r, ""); e == nil {
			t.Fatalf("console accepted a resource with no container: %s/%s", r.Provider, r.Type)
		}
	}
	for _, shell := range []string{"zsh", "sh -c id", "../bin/sh", "sh;id"} {
		if _, e = ConsoleCommand(container, shell); e == nil {
			t.Fatalf("console accepted shell %q", shell)
		}
	}
}

func TestExecCommandRunsInsideTheConsoleContainer(t *testing.T) {
	container := domain.Resource{Provider: "docker", Type: "docker_container", ExternalID: "abc123"}
	cmd, e := ExecCommand(container, " ps aux ")
	if e != nil || cmd.Program != "docker" || strings.Join(cmd.Args, " ") != "exec abc123 sh -c ps aux" {
		t.Fatalf("exec command built wrong: %v %v", cmd, e)
	}
	// The script is one argument, so container shell syntax never reaches the host shell.
	rendered, e := cmd.Render()
	if e != nil {
		t.Fatalf("exec command rejected by the executable allowlist: %v", e)
	}
	if rendered != "docker 'exec' 'abc123' 'sh' '-c' 'ps aux'" {
		t.Fatalf("exec command rendered unquoted: %s", rendered)
	}
	hostile, e := ExecCommand(container, "cat /etc/hosts'; rm -rf / #")
	if e != nil {
		t.Fatalf("shell metacharacters must stay inside the container script: %v", e)
	}
	if rendered, e = hostile.Render(); e != nil || strings.Count(rendered, "docker") != 1 {
		t.Fatalf("quote escape reached the host command line: %s %v", rendered, e)
	}
	service := domain.Resource{Provider: "podman", Type: "podman_container", ExternalID: "c8597c5a76a6"}
	if cmd, e = ExecCommand(service, "id"); e != nil || cmd.Program != "podman" {
		t.Fatalf("podman exec built wrong: %v %v", cmd, e)
	}
	for _, script := range []string{"", "   ", strings.Repeat("a", MaxExecScript+1), "id\x00"} {
		if _, e = ExecCommand(container, script); e == nil {
			t.Fatalf("exec accepted invalid script %q", script)
		}
	}
	for _, r := range []domain.Resource{
		{Provider: "dockercompose", Type: "docker_compose_project", ExternalID: "app"},
		{Provider: "kubernetes", Type: "kubernetes_deployment", ExternalID: "api"},
		{Provider: "docker", Type: "docker_container", ExternalID: "abc;rm -rf /"},
	} {
		if _, e = ExecCommand(r, "id"); e == nil {
			t.Fatalf("exec accepted a resource with no console container: %s/%s", r.Provider, r.Type)
		}
	}
}
