package api

import (
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	hosts, e := s.DB.Hosts(r.Context())
	if e != nil {
		return e
	}
	resources, e := s.DB.Resources(r.Context())
	if e != nil {
		return e
	}
	ops, e := s.Engine.List(r.Context())
	if e != nil {
		return e
	}
	counts := map[string]int{"hosts": 0, "online": 0, "offline": 0, "degraded": 0, "resources": 0, "unhealthy": 0, "active_operations": 0, "pending_approvals": 0, "alerts": 0, "incidents": 0, "deployments": 0, "recommendations": 0}
	hostAccess := map[string]bool{}
	for _, h := range hosts {
		if !rbac.Allowed(p, "host.read", h.Environment) {
			continue
		}
		hostAccess[h.ID] = true
		counts["hosts"]++
		counts[h.State]++
	}
	byProvider := map[string]int{}
	for _, rs := range resources {
		if !hostAccess[rs.HostID] {
			continue
		}
		counts["resources"]++
		byProvider[rs.Provider]++
		if rs.Health == "unhealthy" {
			counts["unhealthy"]++
		}
	}
	recent := []domain.Operation{}
	for _, op := range ops {
		if !rbac.Allowed(p, "operation.read", op.Environment) {
			continue
		}
		if op.State == "running" || op.State == "queued" {
			counts["active_operations"]++
		}
		if op.State == "waiting_approval" {
			counts["pending_approvals"]++
		}
		if len(recent) < 8 {
			op.Parameters = sanitizedOperationParams(op.Parameters)
			recent = append(recent, op)
		}
	}
	for _, kind := range []string{"alerts", "incidents", "deployments", "recommendations"} {
		all, e := s.DB.Objects(r.Context(), kind)
		if e != nil {
			return e
		}
		for _, o := range all {
			if !rbac.Allowed(p, objectKinds[kind].Read, o.Environment) {
				continue
			}
			if kind == "alerts" && domain.String(o.Data, "status") == "resolved" {
				continue
			}
			counts[kind]++
		}
	}
	jsonResponse(w, 200, map[string]any{"counts": counts, "providers": byProvider, "recent_operations": recent, "timestamp": time.Now().UTC()})
	return nil
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "audit.read", ""); e != nil {
		return e
	}
	before := int64(9223372036854775807)
	if raw := r.URL.Query().Get("before"); raw != "" {
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil {
			return bad("invalid cursor")
		}
		before = n
	}
	rows, e := s.DB.Pool.Query(r.Context(), "SELECT to_jsonb(a) FROM audit a WHERE id<$1 ORDER BY id DESC LIMIT 300", before)
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []domain.Event{}
	for rows.Next() {
		var b []byte
		var a domain.Event
		if e = rows.Scan(&b); e != nil {
			return e
		}
		if e = json.Unmarshal(b, &a); e != nil {
			return e
		}
		if rbac.Allowed(p, "audit.read", a.Environment) {
			out = append(out, a)
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	jsonResponse(w, 200, out)
	return nil
}
func (s *Server) events(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return HTTPError{503, "streaming unavailable"}
	}
	cursor := int64(0)
	if raw := r.Header.Get("Last-Event-ID"); raw != "" {
		cursor, _ = strconv.ParseInt(raw, 10, 64)
	} else {
		_ = s.DB.Pool.QueryRow(r.Context(), "SELECT COALESCE(max(id),0) FROM events").Scan(&cursor)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-deadline.C:
			return nil
		case <-tick.C:
			current, e := s.Auth.Authenticate(r)
			if e != nil {
				return nil
			}
			p = current
			rows, e := s.DB.Pool.Query(r.Context(), "SELECT id,topic,environment,payload FROM events WHERE id>$1 ORDER BY id LIMIT 100", cursor)
			if e != nil {
				return nil
			}
			for rows.Next() {
				var id int64
				var topic, env string
				var b []byte
				if e = rows.Scan(&id, &topic, &env, &b); e != nil {
					rows.Close()
					return nil
				}
				cursor = id
				if rbac.Allowed(p, "operation.read", env) {
					_, _ = fmt.Fprintf(w, "id: %d\nevent: change\ndata: %s\n\n", id, b)
				}
			}
			rows.Close()
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
