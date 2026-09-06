package rbac

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"strings"
)

var Roles = []string{"ADMIN", "OPERATOR", "VIEWER", "AUDITOR", "APPROVER"}
var read = []string{"host.read", "resource.read", "container.read", "container.logs", "service.read", "service.logs", "kubernetes.read", "nomad.read", "deployment.read", "operation.read", "alert.read", "incident.read", "llm.use"}

func Permissions(role string) []string {
	p := append([]string{}, read...)
	switch role {
	case "ADMIN":
		return []string{"*"}
	case "OPERATOR":
		p = append(p, "container.create", "container.start", "container.stop", "container.restart", "container.pause", "container.unpause", "container.recreate", "container.up", "container.down", "container.exec", "service.start", "service.stop", "service.restart", "service.reload", "kubernetes.scale", "kubernetes.restart", "kubernetes.delete", "kubernetes.rollback", "kubernetes.deploy", "nomad.run", "nomad.stop", "nomad.restart", "swarm.scale", "swarm.restart", "deployment.execute", "deployment.rollback", "schedule.manage", "incident.manage")
	case "APPROVER":
		p = append(p, "operation.approve", "audit.read")
	case "AUDITOR":
		return append(p, "audit.read")
	case "VIEWER":
	default:
		return nil
	}
	return p
}
func Allowed(p domain.Principal, permission, environment string) bool {
	if !p.User.Enabled {
		return false
	}
	if p.User.Role != "ADMIN" && environment != "" && !domain.Contains(p.User.Environments, "*") && !domain.Contains(p.User.Environments, environment) {
		return false
	}
	perms := Permissions(p.User.Role)
	if !domain.Contains(perms, "*") && !domain.Contains(perms, permission) {
		return false
	}
	if p.TokenID != "" && !domain.Contains(p.Scopes, permission) {
		return false
	}
	return true
}
func Permission(provider, action string) string {
	prefix := "service"
	switch provider {
	case "docker", "dockercompose", "podman", "podmancompose", "provisioning":
		prefix = "container"
	case "kubernetes", "kubernetes-api":
		prefix = "kubernetes"
	case "nomad":
		prefix = "nomad"
	case "swarm":
		prefix = "swarm"
	}
	if action == "logs" {
		if prefix == "kubernetes" || prefix == "nomad" || prefix == "swarm" {
			return "resource.read"
		}
		return prefix + ".logs"
	}
	if strings.HasPrefix(action, "rollout") || action == "inspect" || action == "stats" || action == "describe" || action == "events" || action == "status" {
		return "resource.read"
	}
	return prefix + "." + action
}
