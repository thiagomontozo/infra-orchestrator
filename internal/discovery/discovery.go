package discovery

import (
	"context"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"strings"
	"time"
)

type Service struct {
	DB       *store.DB
	Executor executor.Executor
	Adapters adapters.Registry
}

func (s *Service) Discover(ctx context.Context, h domain.Host) (map[string]any, error) {
	if h.AuthMethod == "kubeconfig" {
		a := s.Adapters["kubernetes-api"]
		rs, e := a.Discover(ctx, h)
		if e != nil {
			h.State = "offline"
			_ = s.DB.ObserveHost(ctx, h)
			return nil, e
		}
		if e = s.DB.UpsertResources(ctx, h.ID, "kubernetes-api", rs); e != nil {
			return nil, e
		}
		now := time.Now().UTC()
		h.State = "online"
		h.LastSeen = &now
		h.Facts = map[string]any{"runtimes": []string{"kubernetes-api"}, "resources": len(rs)}
		if e = s.DB.ObserveHost(ctx, h); e != nil {
			return nil, e
		}
		return h.Facts, nil
	}
	facts := map[string]any{}
	hostname, e := s.Executor.Run(ctx, h, executor.Command{Program: "hostname", Args: []string{"-f"}})
	if e != nil {
		h.State = "offline"
		_ = s.DB.ObserveHost(ctx, h)
		_ = s.DB.Audit(ctx, domain.Event{HostID: h.ID, Environment: h.Environment, ActorType: "worker", Action: "host.offline", Result: "SSH discovery failed"})
		return nil, e
	}
	facts["hostname"] = strings.TrimSpace(hostname.Output)
	for _, probe := range []struct {
		name string
		cmd  executor.Command
	}{{"kernel", executor.Command{Program: "uname", Args: []string{"-srm"}}}, {"os", executor.Command{Program: "cat", Args: []string{"/etc/os-release"}}}, {"cpu", executor.Command{Program: "getconf", Args: []string{"_NPROCESSORS_ONLN"}}}, {"memory", executor.Command{Program: "free", Args: []string{"-b"}}}, {"disk", executor.Command{Program: "df", Args: []string{"-P", "-B1"}}}, {"uptime", executor.Command{Program: "cat", Args: []string{"/proc/uptime"}}}, {"load", executor.Command{Program: "cat", Args: []string{"/proc/loadavg"}}}, {"interfaces", executor.Command{Program: "ip", Args: []string{"-j", "address"}}}} {
		out, e := s.Executor.Run(ctx, h, probe.cmd)
		if e == nil {
			facts[probe.name] = strings.TrimSpace(out.Output)
		}
	}
	detected := []string{}
	failures := map[string]string{}
	count := 0
	for _, name := range []string{"docker", "dockercompose", "systemd", "podman", "podmancompose", "kubernetes", "nomad", "swarm", "supervisor", "pm2"} {
		a := s.Adapters[name]
		ok, _ := a.Detect(ctx, h)
		if !ok {
			continue
		}
		detected = append(detected, name)
		resources, e := a.Discover(ctx, h)
		if e != nil {
			failures[name] = fmt.Sprint(e)
			continue
		}
		if e = s.DB.UpsertResources(ctx, h.ID, name, resources); e != nil {
			return nil, e
		}
		count += len(resources)
	}
	facts["runtimes"] = detected
	facts["discovery_errors"] = failures
	h.Facts = facts
	h.State = "online"
	if len(failures) > 0 {
		h.State = "degraded"
	}
	now := time.Now().UTC()
	h.LastSeen = &now
	if e = s.DB.ObserveHost(ctx, h); e != nil {
		return nil, e
	}
	if e = s.DB.Audit(ctx, domain.Event{HostID: h.ID, Environment: h.Environment, ActorType: "worker", Action: "host.online", Metadata: map[string]any{"resources": count, "runtimes": detected}}); e != nil {
		return nil, e
	}
	return facts, nil
}
