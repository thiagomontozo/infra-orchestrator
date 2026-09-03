package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Name, Env, Address, DatabaseURL, RedisURL, NATSURL, Origin, KnownHosts, VaultURL, VaultToken, SecretBackend, OTELService string
	EncryptionKey                                                                                                            []byte
	SecureCookies, WorkerEnabled, OTEL, Metrics                                                                              bool
	AllowedCIDRs                                                                                                             []string
	SSHTimeout, CommandTimeout, LLMTimeout, SessionTTL                                                                       time.Duration
	Concurrency                                                                                                              int
	OIDCIssuer, OIDCClientID, OIDCClientSecret, OIDCRedirect, OIDCGroupClaim, OIDCRoleMapping, OIDCScopes                    string
	LDAPURL, LDAPBindDN, LDAPBindPassword, LDAPBaseDN, LDAPUserFilter, LDAPGroupAttribute, LDAPRoleMapping                   string
}

func Env(k, fallback string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return fallback
}
func duration(k, fallback string) (time.Duration, error) {
	v, e := time.ParseDuration(Env(k, fallback))
	if e != nil || v <= 0 {
		return 0, fmt.Errorf("invalid %s", k)
	}
	return v, nil
}
func Load() (c Config, err error) {
	c.Name = Env("APP_NAME", "infra-orchestrator")
	c.Env = Env("APP_ENV", "production")
	c.Address = Env("HTTP_ADDRESS", ":"+Env("HTTP_PORT", "8080"))
	c.DatabaseURL = Env("DATABASE_URL", "")
	c.RedisURL = Env("REDIS_URL", "")
	c.NATSURL = Env("NATS_URL", "")
	c.Origin = Env("PUBLIC_ORIGIN", "http://localhost:8080")
	c.KnownHosts = Env("SSH_KNOWN_HOSTS", "")
	c.SecretBackend = Env("SECRET_BACKEND", "local")
	c.VaultURL = Env("VAULT_ADDR", "")
	c.VaultToken = Env("VAULT_TOKEN", "")
	c.SecureCookies = c.Env != "development" && c.Env != "test"
	c.WorkerEnabled = Env("EMBEDDED_WORKER", "true") == "true"
	c.OTEL = Env("OTEL_ENABLED", "false") == "true"
	c.Metrics = Env("PROMETHEUS_ENABLED", "true") == "true"
	c.OTELService = c.Name
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL required")
	}
	c.EncryptionKey, err = base64.StdEncoding.DecodeString(Env("ENCRYPTION_KEY", ""))
	if err != nil || len(c.EncryptionKey) != 32 {
		return c, fmt.Errorf("ENCRYPTION_KEY must be base64 of 32 random bytes")
	}
	if c.SecureCookies && !strings.HasPrefix(c.Origin, "https://") {
		return c, fmt.Errorf("production requires HTTPS PUBLIC_ORIGIN")
	}
	c.AllowedCIDRs = strings.FieldsFunc(Env("OUTBOUND_ALLOWED_CIDRS", ""), func(r rune) bool { return r == ',' })
	c.SSHTimeout, err = duration("SSH_CONNECT_TIMEOUT", "10s")
	if err != nil {
		return
	}
	c.CommandTimeout, err = duration("SSH_COMMAND_TIMEOUT", "90s")
	if err != nil {
		return
	}
	c.LLMTimeout, err = duration("LLM_REQUEST_TIMEOUT", "60s")
	if err != nil {
		return
	}
	c.SessionTTL, err = duration("SESSION_TTL", "8h")
	if err != nil {
		return
	}
	c.Concurrency, err = strconv.Atoi(Env("WORKER_CONCURRENCY", "4"))
	if err != nil || c.Concurrency < 1 || c.Concurrency > 64 {
		return c, fmt.Errorf("WORKER_CONCURRENCY must be 1..64")
	}
	c.OIDCIssuer = Env("OIDC_ISSUER", "")
	c.OIDCClientID = Env("OIDC_CLIENT_ID", "")
	c.OIDCClientSecret = Env("OIDC_CLIENT_SECRET", "")
	c.OIDCRedirect = Env("OIDC_REDIRECT_URI", c.Origin+"/api/v1/auth/oidc/callback")
	c.OIDCGroupClaim = Env("OIDC_GROUP_CLAIM", "groups")
	c.OIDCRoleMapping = Env("OIDC_ROLE_MAPPING", "{}")
	c.OIDCScopes = Env("OIDC_SCOPES", "openid profile email")
	c.LDAPURL = Env("LDAP_URL", "")
	c.LDAPBindDN = Env("LDAP_BIND_DN", "")
	c.LDAPBindPassword = Env("LDAP_BIND_PASSWORD", "")
	c.LDAPBaseDN = Env("LDAP_BASE_DN", "")
	c.LDAPUserFilter = Env("LDAP_USER_FILTER", "(uid=%s)")
	c.LDAPGroupAttribute = Env("LDAP_GROUP_ATTRIBUTE", "memberOf")
	c.LDAPRoleMapping = Env("LDAP_ROLE_MAPPING", "{}")
	if c.LDAPURL != "" && !strings.HasPrefix(c.LDAPURL, "ldaps://") {
		return c, fmt.Errorf("LDAP requires ldaps://")
	}
	return
}
