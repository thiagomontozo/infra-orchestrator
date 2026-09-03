package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"net"
	"net/http"
	"strings"
	"time"
)

var ErrCredentials = errors.New("invalid credentials or verification code")

type Service struct {
	DB        *store.DB
	Cipher    *security.Cipher
	Config    config.Config
	DummyHash string
	Providers map[string]IdentityProvider
}
type Identity struct {
	Subject, Username, Email, Role string
	Groups                         []string
}
type IdentityProvider interface {
	Authenticate(context.Context, string, string) (Identity, error)
}

func New(db *store.DB, c *security.Cipher, cfg config.Config) *Service {
	dummy, _ := security.HashPassword(security.Random(32))
	return &Service{DB: db, Cipher: c, Config: cfg, DummyHash: dummy, Providers: map[string]IdentityProvider{}}
}
func IP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return h
}
func (s *Service) Login(ctx context.Context, login, password, code, method string) (domain.User, bool, error) {
	u, e := s.DB.UserLogin(ctx, login)
	if method == "ldap" {
		p, ok := s.Providers["ldap"]
		if !ok {
			return u, false, ErrCredentials
		}
		id, e := p.Authenticate(ctx, login, password)
		if e != nil {
			return u, false, ErrCredentials
		}
		u, e = s.SyncIdentity(ctx, "ldap", id)
		if e != nil {
			return u, false, e
		}
	} else if method != "local" {
		return u, false, ErrCredentials
	} else {
		hash := s.DummyHash
		if e == nil {
			hash = u.PasswordHash
		}
		valid := security.VerifyPassword(password, hash)
		if !valid || e != nil {
			return u, false, ErrCredentials
		}
	}
	if !u.Enabled || u.Service {
		return u, false, ErrCredentials
	}
	mfa := false
	if u.MFAEnabled {
		secret, e := s.Cipher.Decrypt("mfa:"+u.ID, u.MFASecret)
		if e != nil {
			return u, false, ErrCredentials
		}
		step, ok := security.VerifyTOTP(string(secret), code, time.Now(), u.MFALast)
		if !ok {
			return u, false, ErrCredentials
		}
		tag, e := s.DB.Pool.Exec(ctx, "UPDATE users SET mfa_last=$2 WHERE id=$1 AND mfa_last<$2", u.ID, step)
		if e != nil || tag.RowsAffected() != 1 {
			return u, false, ErrCredentials
		}
		mfa = true
	}
	return u, mfa, nil
}
func (s *Service) SyncIdentity(ctx context.Context, provider string, id Identity) (domain.User, error) {
	if id.Subject == "" || id.Email == "" {
		return domain.User{}, ErrCredentials
	}
	var uid string
	e := s.DB.Pool.QueryRow(ctx, "SELECT id FROM users WHERE external_subject=$1", provider+":"+id.Subject).Scan(&uid)
	if e != nil {
		uid = domain.ID()
		_, e = s.DB.Pool.Exec(ctx, "INSERT INTO users(id,username,email,role,environments,external_subject) VALUES($1,$2,$3,$4,'[]',$5)", uid, id.Username, id.Email, id.Role, provider+":"+id.Subject)
		if e != nil {
			return domain.User{}, fmt.Errorf("external identity provisioning failed")
		}
	} else {
		_, e = s.DB.Pool.Exec(ctx, "UPDATE users SET role=$2,email=$3 WHERE id=$1", uid, id.Role, id.Email)
		if e != nil {
			return domain.User{}, e
		}
	}
	return s.DB.User(ctx, uid)
}
func (s *Service) CreateSession(ctx context.Context, w http.ResponseWriter, r *http.Request, u domain.User, mfa bool, method string) (string, error) {
	token, csrf := security.Random(32), security.Random(32)
	id := domain.ID()
	expires := time.Now().Add(s.Config.SessionTTL)
	tx, e := s.DB.Pool.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, "INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,method,mfa,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", id, u.ID, security.HashToken(token), security.HashToken(csrf), IP(r), security.Bounded(r.UserAgent(), 512, 1), method, mfa, expires)
	if e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, "UPDATE users SET last_login=now() WHERE id=$1", u.ID); e != nil {
		return "", e
	}
	if e = store.AuditTx(ctx, tx, domain.Event{Actor: u.ID, Action: "auth.login", Decision: "allow", SourceIP: IP(r), Metadata: map[string]any{"method": method, "mfa": mfa}}); e != nil {
		return "", e
	}
	if e = tx.Commit(ctx); e != nil {
		return "", e
	}
	s.cookies(w, token, csrf, expires)
	return csrf, nil
}
func (s *Service) cookies(w http.ResponseWriter, token, csrf string, expires time.Time) {
	for _, c := range []*http.Cookie{{Name: "io_session", Value: token, HttpOnly: true}, {Name: "io_csrf", Value: csrf, HttpOnly: false}} {
		c.Path = "/"
		c.Secure = s.Config.SecureCookies
		c.SameSite = http.SameSiteStrictMode
		c.Expires = expires
		http.SetCookie(w, c)
	}
}
func (s *Service) ClearCookies(w http.ResponseWriter) {
	for _, name := range []string{"io_session", "io_csrf"} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: name == "io_session", Secure: s.Config.SecureCookies, SameSite: http.SameSiteStrictMode})
	}
}
func (s *Service) Authenticate(r *http.Request) (p domain.Principal, err error) {
	ctx := r.Context()
	bearer := r.Header.Get("Authorization")
	if bearer != "" {
		if !strings.HasPrefix(bearer, "Bearer io_") {
			return p, ErrCredentials
		}
		var uid string
		var scopes []byte
		err = s.DB.Pool.QueryRow(ctx, "SELECT id,user_id,scopes FROM api_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now()", security.HashToken(strings.TrimPrefix(bearer, "Bearer "))).Scan(&p.TokenID, &uid, &scopes)
		if err != nil {
			return p, ErrCredentials
		}
		p.User, err = s.DB.User(ctx, uid)
		if err != nil || !p.User.Service || !p.User.Enabled {
			return p, ErrCredentials
		}
		err = json.Unmarshal(scopes, &p.Scopes)
		p.AuthMethod = "token"
		return
	}
	c, e := r.Cookie("io_session")
	if e != nil {
		return p, ErrCredentials
	}
	var uid, csrfHash string
	err = s.DB.Pool.QueryRow(ctx, "SELECT id,user_id,csrf_hash,mfa,method FROM sessions WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now()", security.HashToken(c.Value)).Scan(&p.SessionID, &uid, &csrfHash, &p.MFA, &p.AuthMethod)
	if err != nil {
		return p, ErrCredentials
	}
	p.User, err = s.DB.User(ctx, uid)
	if err != nil || !p.User.Enabled {
		return p, ErrCredentials
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		got := security.HashToken(r.Header.Get("X-CSRF-Token"))
		if subtle.ConstantTimeCompare([]byte(got), []byte(csrfHash)) != 1 {
			return p, fmt.Errorf("CSRF validation failed")
		}
		if r.Header.Get("Origin") != s.Config.Origin {
			return p, fmt.Errorf("origin validation failed")
		}
	}
	_, err = s.DB.Pool.Exec(ctx, "UPDATE sessions SET last_seen=now() WHERE id=$1 AND last_seen<now()-interval '30 seconds'", p.SessionID)
	return
}
func (s *Service) Rotate(ctx context.Context, w http.ResponseWriter, p domain.Principal) (string, error) {
	if p.SessionID == "" {
		return "", fmt.Errorf("session required")
	}
	token, csrf := security.Random(32), security.Random(32)
	expiry := time.Now().Add(s.Config.SessionTTL)
	tag, e := s.DB.Pool.Exec(ctx, "UPDATE sessions SET token_hash=$2,csrf_hash=$3,expires_at=LEAST($4,created_at+interval '7 days') WHERE id=$1 AND revoked_at IS NULL AND expires_at>now()", p.SessionID, security.HashToken(token), security.HashToken(csrf), expiry)
	if e != nil || tag.RowsAffected() != 1 {
		return "", ErrCredentials
	}
	s.cookies(w, token, csrf, expiry)
	return csrf, nil
}
