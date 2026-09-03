package policy

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"testing"
	"time"
)

func base() Input {
	return Input{Principal: domain.Principal{User: domain.User{Role: "OPERATOR", Enabled: true, Environments: []string{"*"}}}, Resource: domain.Resource{Provider: "docker"}, Host: domain.Host{Enabled: true, Environment: "production"}, Action: "restart", Now: time.Now()}
}
func TestProductionAndAgent(t *testing.T) {
	in := base()
	d := Evaluate(in, nil)
	if !d.Allowed || !d.Approval {
		t.Fatal("production bypass")
	}
	in.Agent = true
	in.Mode = "ADVISORY"
	if Evaluate(in, nil).Allowed {
		t.Fatal("advisory mutation allowed")
	}
	in.Mode = "AUTOMATED_POLICY_CONTROLLED"
	if Evaluate(in, nil).Allowed {
		t.Fatal("implicit automation allowed")
	}
	d = Evaluate(in, []Rule{{AllowAgent: true}})
	if !d.Allowed || !d.Approval {
		t.Fatal("production automation bypassed approval")
	}
	in.Principal.User.Role = "VIEWER"
	if Evaluate(in, []Rule{{AllowAgent: true}}).Allowed {
		t.Fatal("policy bypassed RBAC")
	}
}
func TestWindowOverMidnight(t *testing.T) {
	w := Window{Days: []int{6}, Start: "22:00", End: "02:00", Timezone: "America/Sao_Paulo"}
	loc, e := time.LoadLocation(w.Timezone)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		s    string
		want bool
	}{{"2026-09-05 23:00", true}, {"2026-09-06 01:00", true}, {"2026-09-06 03:00", false}, {"2026-09-04 23:00", false}} {
		tm, _ := time.ParseInLocation("2006-01-02 15:04", tc.s, loc)
		if w.Contains(tm) != tc.want {
			t.Fatal(tc.s)
		}
	}
}
