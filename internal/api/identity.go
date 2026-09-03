package api

import (
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/auth"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.Config.Origin {
		s.writeError(w, deny("origin validation failed"))
		return
	}
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		Code     string `json:"code"`
		Method   string `json:"method"`
	}
	if e := decode(w, r, &in); e != nil {
		s.writeError(w, e)
		return
	}
	if in.Method == "" {
		in.Method = "local"
	}
	ip := auth.IP(r)
	loginKey := security.HashToken(strings.ToLower(in.Login))
	var blocked bool
	if e := s.DB.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM login_failures WHERE key=$1 AND blocked_until>now())", loginKey).Scan(&blocked); e != nil {
		s.writeError(w, e)
		return
	}
	if blocked {
		s.writeError(w, HTTPError{429, "progressive login lock; try again later"})
		return
	}
	for _, key := range []string{"login-ip:" + ip, "login-user:" + security.HashToken(strings.ToLower(in.Login))} {
		ok, e := s.DB.RateLimit(r.Context(), key, 10, 15*time.Minute)
		if e != nil {
			s.writeError(w, e)
			return
		}
		if !ok {
			s.writeError(w, HTTPError{429, "too many login attempts; retry after 15 minutes"})
			return
		}
	}
	u, mfa, e := s.Auth.Login(r.Context(), in.Login, in.Password, in.Code, in.Method)
	if e != nil {
		_, _ = s.DB.Pool.Exec(r.Context(), "INSERT INTO login_failures(key,failures,blocked_until) VALUES($1,1,now()) ON CONFLICT(key) DO UPDATE SET failures=LEAST(login_failures.failures+1,20),blocked_until=now()+make_interval(secs=>LEAST(900,power(2,LEAST(login_failures.failures,10))::int)),updated_at=now()", loginKey)
		_ = s.DB.Audit(r.Context(), domain.Event{Action: "auth.failed", SourceIP: ip, Decision: "deny", Metadata: map[string]any{"login_hash": security.HashToken(strings.ToLower(in.Login))}})
		s.writeError(w, HTTPError{401, auth.ErrCredentials.Error()})
		return
	}
	_, e = s.DB.Pool.Exec(r.Context(), "DELETE FROM login_failures WHERE key=$1", loginKey)
	if e != nil {
		s.writeError(w, e)
		return
	}
	csrf, e := s.Auth.CreateSession(r.Context(), w, r, u, mfa, in.Method)
	if e != nil {
		s.writeError(w, e)
		return
	}
	jsonResponse(w, 200, map[string]any{"user": u, "csrf_token": csrf, "mfa": mfa, "mfa_enrollment_required": u.MFARequired && !mfa, "permissions": rbac.Permissions(u.Role)})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	jsonResponse(w, 200, map[string]any{"user": p.User, "mfa": p.MFA, "permissions": rbac.Permissions(p.User.Role), "session_id": p.SessionID, "name": s.Config.Name})
	return nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	_, e := s.DB.Pool.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE id=$1", p.SessionID)
	if e != nil {
		return e
	}
	s.Auth.ClearCookies(w)
	if e = s.record(r, p, "auth.logout", "", nil); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) renew(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	csrf, e := s.Auth.Rotate(r.Context(), w, p)
	if e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]string{"csrf_token": csrf})
	return nil
}
func (s *Server) password(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		Current  string `json:"current_password"`
		Password string `json:"password"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !security.VerifyPassword(in.Current, p.User.PasswordHash) {
		return deny("current password is incorrect")
	}
	h, e := security.HashPassword(in.Password)
	if e != nil {
		return bad(e.Error())
	}
	tx, e := s.DB.Pool.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "UPDATE users SET password_hash=$2,force_password=false WHERE id=$1", p.User.ID, h); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2", p.User.ID, p.SessionID); e != nil {
		return e
	}
	if e = store.AuditTx(r.Context(), tx, domain.Event{Actor: p.User.ID, Action: "auth.password_changed"}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) mfaEnroll(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if p.SessionID == "" || p.User.MFAEnabled {
		return bad("TOTP is already enabled or session required")
	}
	secret := security.NewTOTPSecret()
	if e := s.Secrets.Put(r.Context(), "mfa-pending-"+p.User.ID, []byte(secret)); e != nil {
		return e
	}
	uri := "otpauth://totp/" + url.PathEscape(s.Config.Name+":"+p.User.Username) + "?secret=" + secret + "&issuer=" + url.QueryEscape(s.Config.Name)
	jsonResponse(w, 200, map[string]string{"secret": secret, "uri": uri})
	return s.record(r, p, "auth.mfa_enrollment_started", "", nil)
}
func (s *Server) mfaVerify(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if p.SessionID == "" || p.User.MFAEnabled {
		return bad("TOTP enrollment unavailable")
	}
	var in struct {
		Code string `json:"code"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	ok, e := s.DB.RateLimit(r.Context(), "mfa:"+p.User.ID, 5, 5*time.Minute)
	if e != nil {
		return e
	}
	if !ok {
		return HTTPError{429, "MFA attempt limit reached"}
	}
	secret, e := s.Secrets.Get(r.Context(), "mfa-pending-"+p.User.ID)
	if e != nil {
		return bad("start MFA enrollment first")
	}
	step, valid := security.VerifyTOTP(string(secret), in.Code, time.Now(), -1)
	if !valid {
		return deny("invalid TOTP code")
	}
	encrypted, e := s.Auth.Cipher.Encrypt("mfa:"+p.User.ID, secret)
	if e != nil {
		return e
	}
	tx, e := s.DB.Pool.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "UPDATE users SET mfa_secret=$2,mfa_last=$3 WHERE id=$1 AND mfa_secret=''", p.User.ID, encrypted, step); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE sessions SET mfa=true WHERE id=$1", p.SessionID); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2", p.User.ID, p.SessionID); e != nil {
		return e
	}
	if e = store.AuditTx(r.Context(), tx, domain.Event{Actor: p.User.ID, Action: "auth.mfa_enabled"}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	_ = s.Secrets.Delete(r.Context(), "mfa-pending-"+p.User.ID)
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) users(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	v, e := s.DB.Users(r.Context())
	if e != nil {
		return e
	}
	jsonResponse(w, 200, v)
	return nil
}

type userInput struct {
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	Password      string   `json:"password"`
	Role          string   `json:"role"`
	Enabled       bool     `json:"enabled"`
	Environments  []string `json:"environments"`
	MFARequired   bool     `json:"mfa_required"`
	ForcePassword bool     `json:"force_password_change"`
	Service       bool     `json:"service_account"`
}

func validateUser(in userInput) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.@+-]{3,128}$`).MatchString(in.Username) {
		return bad("invalid username")
	}
	if _, e := mail.ParseAddress(in.Email); e != nil {
		return bad("invalid email")
	}
	if !domain.Contains(rbac.Roles, in.Role) {
		return bad("invalid role")
	}
	if len(in.Environments) == 0 {
		return bad("at least one environment scope required")
	}
	for _, env := range in.Environments {
		if env != "*" && !validEnv(env) {
			return bad("invalid environment")
		}
	}
	return nil
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	var in userInput
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := validateUser(in); e != nil {
		return e
	}
	hash := ""
	if !in.Service {
		var e error
		hash, e = security.HashPassword(in.Password)
		if e != nil {
			return bad(e.Error())
		}
	}
	u := domain.User{ID: domain.ID(), Username: in.Username, Email: in.Email, PasswordHash: hash, Role: in.Role, Enabled: in.Enabled, Environments: in.Environments, MFARequired: in.MFARequired, ForcePassword: in.ForcePassword, Service: in.Service}
	if e := s.DB.CreateUser(r.Context(), u); e != nil {
		return bad("user could not be created; check unique username/email")
	}
	if e := s.record(r, p, "user.created", "", map[string]any{"user_id": u.ID, "role": u.Role}); e != nil {
		return e
	}
	jsonResponse(w, 201, u)
	return nil
}
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	var in userInput
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := validateUser(in); e != nil {
		return e
	}
	id := r.PathValue("id")
	u, e := s.DB.User(r.Context(), id)
	if e != nil {
		return e
	}
	if in.Service != u.Service {
		return bad("account type cannot be changed")
	}
	tx, e := s.DB.Pool.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(8915121)"); e != nil {
		return e
	}
	if u.Role == "ADMIN" && (!in.Enabled || in.Role != "ADMIN") {
		var n int
		if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM users WHERE role='ADMIN' AND enabled=true AND service=false AND id<>$1", id).Scan(&n); e != nil {
			return e
		}
		if n == 0 {
			return deny("cannot disable or demote the last administrator")
		}
	}
	env, _ := json.Marshal(in.Environments)
	if _, e = tx.Exec(r.Context(), "UPDATE users SET username=$2,email=$3,role=$4,enabled=$5,environments=$6,mfa_required=$7,force_password=$8 WHERE id=$1", id, in.Username, in.Email, in.Role, in.Enabled, env, in.MFARequired, in.ForcePassword); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE user_id=$1", id); e != nil {
		return e
	}
	if e = store.AuditTx(r.Context(), tx, domain.Event{Actor: p.User.ID, Action: "user.updated", Metadata: map[string]any{"user_id": id, "role": in.Role}}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	id := r.PathValue("id")
	u, e := s.DB.User(r.Context(), id)
	if e != nil {
		return e
	}
	if u.Role == "ADMIN" {
		return deny("demote the administrator before deletion")
	} // Logical deletion preserves operation and audit references.
	tx, e := s.DB.Pool.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "UPDATE users SET enabled=false,password_hash='',mfa_secret='' WHERE id=$1", id); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE user_id=$1", id); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE api_tokens SET revoked_at=now() WHERE user_id=$1", id); e != nil {
		return e
	}
	if e = store.AuditTx(r.Context(), tx, domain.Event{Actor: p.User.ID, Action: "user.deleted", Metadata: map[string]any{"user_id": id}}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	var in struct {
		Password string `json:"password"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	hash, e := security.HashPassword(in.Password)
	if e != nil {
		return bad(e.Error())
	}
	id := r.PathValue("id")
	tx, e := s.DB.Pool.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "UPDATE users SET password_hash=$2,force_password=true WHERE id=$1 AND service=false", id, hash); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE user_id=$1", id); e != nil {
		return e
	}
	if e = store.AuditTx(r.Context(), tx, domain.Event{Actor: p.User.ID, Action: "user.password_reset", Metadata: map[string]any{"user_id": id}}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) sessions(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	rows, e := s.DB.Pool.Query(r.Context(), "SELECT jsonb_build_object('id',s.id,'user_id',s.user_id,'username',u.username,'ip',s.ip,'user_agent',s.user_agent,'created_at',s.created_at,'last_seen',s.last_seen,'expires_at',s.expires_at,'method',s.method,'mfa',s.mfa,'current',s.id=$2,'revoked_at',s.revoked_at) FROM sessions s JOIN users u ON u.id=s.user_id WHERE ($3 OR s.user_id=$1) ORDER BY s.created_at DESC LIMIT 500", p.User.ID, p.SessionID, rbac.Allowed(p, "user.manage", ""))
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b json.RawMessage
		if e = rows.Scan(&b); e != nil {
			return e
		}
		out = append(out, b)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	jsonResponse(w, 200, out)
	return nil
}
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	tag, e := s.DB.Pool.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE id=$1 AND ($3 OR user_id=$2)", r.PathValue("id"), p.User.ID, rbac.Allowed(p, "user.manage", ""))
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return deny("session not found or unauthorized")
	}
	if e = s.record(r, p, "session.revoked", "", map[string]any{"session_id": r.PathValue("id")}); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) revokeUserSessions(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	id := r.PathValue("id")
	if id != p.User.ID {
		if e := require(p, "user.manage", ""); e != nil {
			return e
		}
	}
	if _, e := s.DB.Pool.Exec(r.Context(), "UPDATE sessions SET revoked_at=now() WHERE user_id=$1", id); e != nil {
		return e
	}
	if e := s.record(r, p, "session.user_revoked", "", map[string]any{"user_id": id}); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) roles(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	out := map[string][]string{}
	for _, role := range rbac.Roles {
		out[role] = rbac.Permissions(role)
	}
	jsonResponse(w, 200, out)
	return nil
}
func (s *Server) tokens(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	rows, e := s.DB.Pool.Query(r.Context(), "SELECT to_jsonb(t)-'token_hash' FROM api_tokens t ORDER BY created_at DESC LIMIT 500")
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b json.RawMessage
		if e = rows.Scan(&b); e != nil {
			return e
		}
		out = append(out, b)
	}
	jsonResponse(w, 200, out)
	return rows.Err()
}
func (s *Server) createToken(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	var in struct {
		UserID    string    `json:"user_id"`
		Name      string    `json:"name"`
		Scopes    []string  `json:"scopes"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	u, e := s.DB.User(r.Context(), in.UserID)
	if e != nil {
		return e
	}
	if !u.Service || !u.Enabled || len(in.Scopes) == 0 || !in.ExpiresAt.After(time.Now()) || in.ExpiresAt.After(time.Now().Add(365*24*time.Hour)) {
		return bad("enabled service account, scopes and expiry within one year required")
	}
	for _, scope := range in.Scopes {
		if scope == "*" || !rbac.Allowed(domain.Principal{User: u}, scope, "") {
			return bad("scope exceeds service account role")
		}
	}
	token := "io_" + security.Random(32)
	id := domain.ID()
	scopes, _ := json.Marshal(in.Scopes)
	_, e = s.DB.Pool.Exec(r.Context(), "INSERT INTO api_tokens(id,user_id,name,token_hash,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6)", id, u.ID, in.Name, security.HashToken(token), scopes, in.ExpiresAt)
	if e != nil {
		return e
	}
	if e = s.record(r, p, "token.created", "", map[string]any{"token_id": id, "user_id": u.ID, "scopes": in.Scopes}); e != nil {
		return e
	}
	jsonResponse(w, 201, map[string]string{"id": id, "token": token})
	return nil
}
func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "user.manage", ""); e != nil {
		return e
	}
	_, e := s.DB.Pool.Exec(r.Context(), "UPDATE api_tokens SET revoked_at=now() WHERE id=$1", r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = s.record(r, p, "token.revoked", "", map[string]any{"token_id": r.PathValue("id")}); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}

var _ = fmt.Sprint
