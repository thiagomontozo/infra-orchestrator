package config

import (
	"crypto/x509"
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
	LDAPURL, LDAPBindDN, LDAPBindPassword, LDAPBaseDN, LDAPUserFilter, LDAPGroupAttribute, LDAPRoleMapping, LDAPDomain       string
	LDAPStartTLS, LDAPAllowPlaintext, LDAPSkipVerify                                                                         bool
	LDAPCACert                                                                                                               string
	LDAPCAPool                                                                                                               *x509.CertPool
}

func Env(k, fallback string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return fallback
}

// EnvSet treats an empty variable as unset, so a blank line in a .env file still falls back to the default.
func EnvSet(k, fallback string) string {
	if v := Env(k, ""); v != "" {
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
	c.LDAPDomain = strings.Trim(Env("LDAP_DOMAIN", ""), ".")
	c.LDAPURL = LDAPEndpoint(Env("LDAP_SERVER", ""), Env("LDAP_URL", ""))
	c.LDAPBindDN = Env("LDAP_BIND_DN", "")
	c.LDAPBindPassword = Env("LDAP_BIND_PASSWORD", "")
	c.LDAPBaseDN = EnvSet("LDAP_BASE_DN", BaseDN(c.LDAPDomain))
	c.LDAPGroupAttribute = EnvSet("LDAP_GROUP_ATTRIBUTE", "memberOf")
	c.LDAPRoleMapping = EnvSet("LDAP_ROLE_MAPPING", "{}")
	c.LDAPStartTLS = EnvSet("LDAP_STARTTLS", "true") == "true"
	c.LDAPAllowPlaintext = EnvSet("LDAP_ALLOW_PLAINTEXT", "false") == "true"
	c.LDAPSkipVerify = EnvSet("LDAP_TLS_SKIP_VERIFY", "false") == "true"
	c.LDAPCACert = Env("LDAP_CA_CERT", "")
	if c.LDAPDomain != "" {
		c.LDAPUserFilter = EnvSet("LDAP_USER_FILTER", "(sAMAccountName=%s)")
	} else {
		c.LDAPUserFilter = EnvSet("LDAP_USER_FILTER", "(uid=%s)")
	}
	if c.LDAPURL == "" {
		return
	}
	if !strings.HasPrefix(c.LDAPURL, "ldaps://") && !strings.HasPrefix(c.LDAPURL, "ldap://") {
		return c, fmt.Errorf("LDAP requires ldaps:// or ldap://")
	}
	if c.LDAPBaseDN == "" {
		return c, fmt.Errorf("LDAP requires LDAP_BASE_DN or LDAP_DOMAIN")
	}
	if c.LDAPDomain == "" && c.LDAPBindDN == "" {
		return c, fmt.Errorf("LDAP requires LDAP_DOMAIN (Active Directory) or LDAP_BIND_DN (search account)")
	}
	if strings.HasPrefix(c.LDAPURL, "ldap://") && !c.LDAPStartTLS && !c.LDAPAllowPlaintext {
		return c, fmt.Errorf("ldap:// sends credentials in clear text; set LDAP_STARTTLS=true or LDAP_ALLOW_PLAINTEXT=true")
	}
	if c.LDAPCACert != "" {
		pem, e := os.ReadFile(c.LDAPCACert)
		if e != nil {
			return c, fmt.Errorf("LDAP_CA_CERT unreadable: %w", e)
		}
		c.LDAPCAPool = x509.NewCertPool()
		if !c.LDAPCAPool.AppendCertsFromPEM(pem) {
			return c, fmt.Errorf("LDAP_CA_CERT holds no PEM certificate")
		}
	}
	return
}

// LDAPEndpoint normalizes LDAP_SERVER (bare host, host:port or URL) into a dial URL, falling back to LDAP_URL.
func LDAPEndpoint(server, url string) string {
	if server == "" {
		return url
	}
	if strings.Contains(server, "://") {
		return server
	}
	if !strings.Contains(server, ":") {
		return "ldap://" + server + ":389"
	}
	return "ldap://" + server
}

// BaseDN derives the directory root from an Active Directory domain: CORP.EXAMPLE.COM -> DC=CORP,DC=EXAMPLE,DC=COM.
func BaseDN(domain string) string {
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}
