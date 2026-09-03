package api

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"net/http"
)

func (s *Server) createCluster(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		Name        string `json:"name"`
		Environment string `json:"environment"`
		Kubeconfig  string `json:"kubeconfig"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := require(p, "host.create", in.Environment); e != nil {
		return e
	}
	if !validEnv(in.Environment) || in.Name == "" {
		return bad("name and environment required")
	}
	if _, e := adapters.ParseKubeconfig([]byte(in.Kubeconfig)); e != nil {
		return bad(e.Error())
	}
	sid := domain.ID()
	if e := s.Secrets.Put(r.Context(), sid, []byte(in.Kubeconfig)); e != nil {
		return e
	}
	h := domain.Host{ID: domain.ID(), Name: in.Name, Hostname: "kubernetes-api", AuthMethod: "kubeconfig", SecretID: sid, Environment: in.Environment, Enabled: true, State: "unknown", Facts: map[string]any{"runtimes": []string{"kubernetes-api"}}}
	if e := s.DB.SaveHost(r.Context(), h); e != nil {
		return e
	}
	if e := s.record(r, p, "kubernetes.cluster_registered", h.Environment, map[string]any{"host_id": h.ID}); e != nil {
		return e
	}
	jsonResponse(w, 201, h)
	return nil
}
