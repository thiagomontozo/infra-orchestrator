package adapters

import (
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
)

// ConsoleTarget is the container an interactive session attaches to, after the
// resource has been resolved to something that actually has one.
type ConsoleTarget struct {
	Provider  string
	Container string
	Shell     string
}

// consoleShells is the whole set of programs a session may start inside the
// container. Anything else is refused before a command is built.
var consoleShells = map[string]bool{"sh": true, "bash": true}

// ConsoleCommand resolves a resource to a container and builds the exec command
// for it. Resources that are not a single container -- a compose project, a
// kubernetes object, a systemd unit -- are refused, because there is nothing to
// attach to. The command goes through Command.Render like every other remote
// call, so the host binary allowlist still applies.
func ConsoleCommand(r domain.Resource, shell string) (executor.Command, ConsoleTarget, error) {
	var empty executor.Command
	var t ConsoleTarget
	if shell == "" {
		shell = "sh"
	}
	if !consoleShells[shell] {
		return empty, t, fmt.Errorf("shell not allowed")
	}
	container := ""
	program := "docker"
	switch r.Provider {
	case "docker", "podman":
		if r.Type == "docker_container" || r.Type == "podman_container" {
			container = r.ExternalID
		}
	case "dockercompose", "podmancompose":
		if r.Type == "docker_compose_service" {
			container = domain.String(r.Metadata, "container")
		}
	}
	if r.Provider == "podman" || r.Provider == "podmancompose" {
		program = "podman"
	}
	if container == "" {
		return empty, t, fmt.Errorf("resource has no attachable container")
	}
	if !executor.ValidRef(container) {
		return empty, t, fmt.Errorf("invalid container identifier")
	}
	cmd := executor.Command{Program: program, Args: []string{"exec", "--interactive", "--tty", container, shell}}
	if _, e := cmd.Render(); e != nil {
		return empty, t, e
	}
	return cmd, ConsoleTarget{Provider: r.Provider, Container: container, Shell: shell}, nil
}
