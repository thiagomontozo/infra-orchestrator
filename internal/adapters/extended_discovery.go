package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
)

func (a *CLI) extendDiscovery(ctx context.Context, h domain.Host, resources []domain.Resource) ([]domain.Resource, error) {
	if a.Provider == "nomad" {
		base := append([]domain.Resource{}, resources...)
		for _, job := range base {
			if !executor.ValidRef(job.ExternalID) {
				continue
			}
			out, e := a.Executor.Run(ctx, h, a.command("job", "allocs", "-json", job.ExternalID))
			if e != nil {
				continue
			}
			var allocations []map[string]any
			if e = json.Unmarshal([]byte(out.Output), &allocations); e != nil {
				return nil, e
			}
			groups := map[string]bool{}
			for _, m := range allocations {
				group := text(m, "TaskGroup")
				groups[group] = true
				state := text(m, "ClientStatus")
				resources = append(resources, domain.Resource{ExternalID: text(m, "ID"), Name: job.Name + "/" + text(m, "ID"), Type: "nomad_allocation", Namespace: job.Namespace, State: state, Health: health(state), Metadata: map[string]any{"job_id": job.ExternalID, "group": group, "node_id": m["NodeID"], "task_states": m["TaskStates"], "deployment_id": m["DeploymentID"]}})
			}
			for group := range groups {
				resources = append(resources, domain.Resource{ExternalID: job.ExternalID + "/group/" + group, Name: group, Type: "nomad_group", State: job.State, Health: job.Health, Metadata: map[string]any{"job_id": job.ExternalID}})
			}
		}
		out, e := a.Executor.Run(ctx, h, a.command("node", "status", "-json"))
		if e == nil {
			var nodes []map[string]any
			if json.Unmarshal([]byte(out.Output), &nodes) == nil {
				for _, n := range nodes {
					resources = append(resources, domain.Resource{ExternalID: "node/" + text(n, "ID"), Name: text(n, "Name"), Type: "nomad_node", State: text(n, "Status"), Health: health(text(n, "Status")), Metadata: map[string]any{"id": n["ID"], "datacenter": n["Datacenter"], "drain": n["Drain"]}})
				}
			}
		}
	}
	if a.Provider == "dockercompose" {
		base := append([]domain.Resource{}, resources...)
		for _, project := range base {
			if !executor.ValidRef(project.Name) {
				continue
			}
			out, e := a.Executor.Run(ctx, h, a.command("--project-name", project.Name, "ps", "--all", "--format", "json"))
			if e != nil {
				continue
			}
			rows, e := decodeRows([]byte(out.Output))
			if e != nil {
				return nil, e
			}
			seen := map[string]bool{}
			for _, row := range rows {
				service := text(row, "Service")
				if service == "" || seen[service] {
					continue
				}
				seen[service] = true
				state := text(row, "State")
				resources = append(resources, domain.Resource{ExternalID: project.Name + "/" + service, Name: project.Name + " / " + service, Type: "docker_compose_service", State: state, Health: health(state), Metadata: map[string]any{"project": project.Name, "service": service, "config_files": project.Metadata["config_files"], "container": text(row, "ID"), "image": text(row, "Image")}})
			}
		}
	}
	if a.Provider == "swarm" {
		for _, probe := range []struct {
			args []string
			kind string
		}{{[]string{"node", "ls", "--format", "{{json .}}"}, "docker_swarm_node"}, {[]string{"stack", "ls", "--format", "{{json .}}"}, "docker_swarm_stack"}} {
			out, e := a.Executor.Run(ctx, h, a.command(probe.args...))
			if e != nil {
				continue
			}
			rows, e := decodeRows([]byte(out.Output))
			if e != nil {
				return nil, e
			}
			for _, m := range rows {
				id := text(m, "ID", "Name")
				resources = append(resources, domain.Resource{ExternalID: probe.kind + "/" + id, Name: text(m, "Hostname", "Name"), Type: probe.kind, State: text(m, "Status", "Services"), Health: "unknown", Metadata: m})
			}
		}
	}
	return resources, nil
}

var _ = fmt.Sprint
