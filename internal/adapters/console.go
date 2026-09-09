package adapters

import (
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"strings"
)

// consoleShells are the only programs a console session may start inside the container.
var consoleShells = map[string]bool{"sh": true, "bash": true}

// ConsoleTarget returns the container a console session attaches to, and the CLI that
// reaches it. Only container-backed resources qualify: a compose project has no single
// container, so the caller must pick one of its services first.
func ConsoleTarget(r domain.Resource) (program, container string, err error) {
	switch r.Provider {
	case "docker", "dockercompose":
		program = "docker"
	case "podman", "podmancompose":
		program = "podman"
	default:
		return "", "", fmt.Errorf("console is not available for provider %q", r.Provider)
	}
	switch r.Type {
	case "docker_container", "podman_container":
		container = r.ExternalID
	case "docker_compose_service":
		container = domain.String(r.Metadata, "container")
	default:
		return "", "", fmt.Errorf("console requires a container; %q does not map to one", r.Type)
	}
	if container == "" {
		return "", "", fmt.Errorf("resource has no container to attach to")
	}
	if !executor.ValidRef(container) {
		return "", "", fmt.Errorf("invalid container identifier")
	}
	return program, container, nil
}

// ConsoleCommand builds the interactive shell command for a container-backed resource.
// The shell is restricted to a fixed set so the argument cannot carry anything else.
func ConsoleCommand(r domain.Resource, shell string) (executor.Command, error) {
	var empty executor.Command
	if shell == "" {
		shell = "sh"
	}
	if !consoleShells[shell] {
		return empty, fmt.Errorf("unsupported console shell")
	}
	program, container, e := ConsoleTarget(r)
	if e != nil {
		return empty, e
	}
	return executor.Command{Program: program, Args: []string{"exec", "--interactive", "--tty", container, shell}}, nil
}

// MaxExecScript bounds a single non-interactive command. It is far below the argument
// limit the renderer enforces, so a runaway script is rejected here with a message the
// caller can show rather than deep inside the executor.
const MaxExecScript = 2000

// ExecCommand builds a one-shot command that runs inside the same container a console
// session would attach to. The script reaches the container's own shell as a single
// quoted argument, so it cannot break out into the host command line; what it is allowed
// to do inside the container is decided by the caller's permissions, not here.
func ExecCommand(r domain.Resource, script string) (executor.Command, error) {
	var empty executor.Command
	script = strings.TrimSpace(script)
	switch {
	case script == "":
		return empty, fmt.Errorf("empty command")
	case len(script) > MaxExecScript:
		return empty, fmt.Errorf("command exceeds %d characters", MaxExecScript)
	case strings.ContainsRune(script, 0):
		return empty, fmt.Errorf("command contains a null byte")
	}
	program, container, e := ConsoleTarget(r)
	if e != nil {
		return empty, e
	}
	return executor.Command{Program: program, Args: []string{"exec", container, "sh", "-c", script}}, nil
}
