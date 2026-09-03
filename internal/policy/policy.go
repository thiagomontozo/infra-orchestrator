package policy

import (
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"strings"
	"time"
)

type Window struct {
	Days     []int  `json:"days"`
	Start    string `json:"start"`
	End      string `json:"end"`
	Timezone string `json:"timezone"`
}

func (w Window) Contains(t time.Time) bool {
	loc, e := time.LoadLocation(w.Timezone)
	if e != nil {
		return false
	}
	t = t.In(loc)
	start, e := time.Parse("15:04", w.Start)
	if e != nil {
		return false
	}
	end, e := time.Parse("15:04", w.End)
	if e != nil {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	a, b := start.Hour()*60+start.Minute(), end.Hour()*60+end.Minute()
	day := int(t.Weekday())
	if a > b && m < b {
		day = (day + 6) % 7
	}
	found := false
	for _, d := range w.Days {
		if d == day {
			found = true
		}
	}
	if !found {
		return false
	}
	if a > b {
		return m >= a || m < b
	}
	return m >= a && m < b
}

type Rule struct {
	ID          string  `json:"id"`
	Environment string  `json:"environment"`
	Action      string  `json:"action"`
	Role        string  `json:"role"`
	UserID      string  `json:"user_id"`
	HostID      string  `json:"host_id"`
	Group       string  `json:"group"`
	ResourceID  string  `json:"resource_id"`
	Risk        string  `json:"risk"`
	Deny        bool    `json:"deny"`
	Approval    bool    `json:"approval_required"`
	RequireMFA  bool    `json:"require_mfa"`
	AllowAgent  bool    `json:"allow_agent"`
	Window      *Window `json:"window"`
}
type Input struct {
	Principal domain.Principal
	Resource  domain.Resource
	Host      domain.Host
	Action    string
	Agent     bool
	Mode      string
	Now       time.Time
}
type Decision struct {
	Allowed  bool   `json:"allowed"`
	Approval bool   `json:"approval_required"`
	Risk     string `json:"risk"`
	Reason   string `json:"reason"`
}

func Risk(action string) string {
	switch action {
	case "delete", "down", "recreate", "deploy", "run", "stop", "rollback", "create":
		return "high"
	case "restart", "scale", "reload", "pause":
		return "medium"
	}
	return "low"
}
func ReadOnly(action string) bool {
	return domain.Contains([]string{"logs", "inspect", "stats", "describe", "events", "status", "rollout_status", "rollout_history"}, action)
}
func Evaluate(in Input, rules []Rule) Decision {
	d := Decision{Risk: Risk(in.Action)}
	deny := func(s string) Decision { d.Allowed = false; d.Reason = s; return d }
	if !rbac.Allowed(in.Principal, rbac.Permission(in.Resource.Provider, in.Action), in.Host.Environment) {
		return deny("RBAC denied")
	}
	if !in.Host.Enabled {
		return deny("host disabled")
	}
	if in.Principal.User.ForcePassword {
		return deny("password change required")
	}
	if in.Principal.User.MFARequired && !in.Principal.MFA {
		return deny("MFA required")
	}
	if in.Agent && (in.Mode == "DISABLED" || in.Mode == "ADVISORY") {
		return deny("agent mode does not allow mutation")
	}
	d.Approval = in.Host.Environment == "production" && !ReadOnly(in.Action)
	if in.Agent && in.Mode == "ASSISTED" {
		d.Approval = true
	}
	autoAllowed := false
	for _, r := range rules {
		if r.Environment != "" && r.Environment != in.Host.Environment {
			continue
		}
		if r.Action != "" && r.Action != "*" && r.Action != in.Action {
			continue
		}
		if r.Role != "" && r.Role != in.Principal.User.Role {
			continue
		}
		if r.UserID != "" && r.UserID != in.Principal.User.ID {
			continue
		}
		if r.HostID != "" && r.HostID != in.Host.ID {
			continue
		}
		if r.ResourceID != "" && r.ResourceID != in.Resource.ID {
			continue
		}
		if r.Group != "" && !domain.Contains(in.Host.Groups, r.Group) {
			continue
		}
		if r.Risk != "" && r.Risk != d.Risk {
			continue
		}
		if r.Deny {
			return deny("policy denied: " + r.ID)
		}
		if r.RequireMFA && !in.Principal.MFA {
			return deny("policy requires MFA")
		}
		if r.Window != nil && !r.Window.Contains(in.Now) {
			return deny("outside maintenance window")
		}
		d.Approval = d.Approval || r.Approval
		autoAllowed = autoAllowed || r.AllowAgent
	}
	if in.Agent && in.Mode == "AUTOMATED_POLICY_CONTROLLED" && !autoAllowed {
		return deny("explicit automation policy required")
	}
	d.Allowed = true
	d.Reason = "authorized"
	return d
}
func Validate(r Rule) error {
	if r.Window != nil {
		if _, e := time.LoadLocation(r.Window.Timezone); e != nil {
			return e
		}
		for _, v := range []string{r.Window.Start, r.Window.End} {
			if _, e := time.Parse("15:04", v); e != nil {
				return e
			}
		}
		if len(r.Window.Days) == 0 {
			return fmt.Errorf("window days required")
		}
		for _, d := range r.Window.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("invalid weekday")
			}
		}
	}
	if strings.ContainsAny(r.Action, "\n\r") {
		return fmt.Errorf("invalid action")
	}
	return nil
}
