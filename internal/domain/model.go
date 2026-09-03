package domain

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

type User struct {
	ID            string     `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	Role          string     `json:"role"`
	Enabled       bool       `json:"enabled"`
	Environments  []string   `json:"environments"`
	MFARequired   bool       `json:"mfa_required"`
	MFAEnabled    bool       `json:"mfa_enabled"`
	ForcePassword bool       `json:"force_password_change"`
	Service       bool       `json:"service_account"`
	LastLogin     *time.Time `json:"last_login"`
	PasswordHash  string     `json:"-"`
	MFASecret     string     `json:"-"`
	MFALast       int64      `json:"-"`
}
type Principal struct {
	User       User
	SessionID  string
	TokenID    string
	Scopes     []string
	MFA        bool
	AuthMethod string
}
type Host struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Hostname    string         `json:"hostname"`
	Port        int            `json:"port"`
	Username    string         `json:"username"`
	AuthMethod  string         `json:"auth_method"`
	SecretID    string         `json:"-"`
	Fingerprint string         `json:"fingerprint"`
	Environment string         `json:"environment"`
	Groups      []string       `json:"groups"`
	Tags        []string       `json:"tags"`
	Enabled     bool           `json:"enabled"`
	BastionID   string         `json:"bastion_id"`
	State       string         `json:"state"`
	Facts       map[string]any `json:"facts"`
	LastSeen    *time.Time     `json:"last_seen"`
}
type Resource struct {
	ID           string            `json:"id"`
	HostID       string            `json:"host_id"`
	Type         string            `json:"type"`
	Provider     string            `json:"provider"`
	Name         string            `json:"name"`
	ExternalID   string            `json:"external_id"`
	Namespace    string            `json:"namespace"`
	State        string            `json:"state"`
	Health       string            `json:"health"`
	Capabilities []string          `json:"capabilities"`
	Metadata     map[string]any    `json:"metadata"`
	Labels       map[string]string `json:"labels"`
	Environment  string            `json:"environment"`
	DiscoveredAt time.Time         `json:"discovered_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}
type Operation struct {
	ID          string         `json:"id"`
	Requester   string         `json:"requester"`
	ResourceID  string         `json:"resource_id"`
	HostID      string         `json:"host_id"`
	Action      string         `json:"action"`
	Parameters  map[string]any `json:"parameters"`
	Environment string         `json:"environment"`
	Risk        string         `json:"risk"`
	State       string         `json:"state"`
	RequestID   string         `json:"request_id"`
	ApprovalBy  string         `json:"approval_by"`
	Reason      string         `json:"reason"`
	Agent       bool           `json:"agent"`
	AgentMode   string         `json:"agent_mode"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at"`
	FinishedAt  *time.Time     `json:"finished_at"`
	Result      string         `json:"result"`
	Error       string         `json:"error"`
	LeaseUntil  *time.Time     `json:"lease_until"`
	WorkerID    string         `json:"worker_id"`
	BatchID     string         `json:"batch_id"`
	BatchIndex  int            `json:"batch_index"`
	AuthMFA     bool           `json:"-"`
}
type Event struct {
	ID          int64          `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Actor       string         `json:"actor"`
	ActorType   string         `json:"actor_type"`
	SourceIP    string         `json:"source_ip"`
	RequestID   string         `json:"request_id"`
	HostID      string         `json:"host_id"`
	ResourceID  string         `json:"resource_id"`
	Environment string         `json:"environment"`
	Action      string         `json:"action"`
	Decision    string         `json:"decision"`
	Result      string         `json:"result"`
	Metadata    map[string]any `json:"metadata"`
}
type Object struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	Environment string         `json:"environment"`
	Data        map[string]any `json:"data"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

func Contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func String(m map[string]any, k string) string  { v, _ := m[k].(string); return v }
func Number(m map[string]any, k string) float64 { v, _ := m[k].(float64); return v }
func Bool(m map[string]any, k string) bool      { v, _ := m[k].(bool); return v }
