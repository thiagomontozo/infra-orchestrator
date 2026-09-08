package config

import "testing"

func TestLDAPEndpoint(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.10": "ldap://192.0.2.10:389", "192.0.2.10:3268": "ldap://192.0.2.10:3268", "ldaps://ad.example.com:636": "ldaps://ad.example.com:636", "": "ldaps://legacy:636"} {
		if got := LDAPEndpoint(in, "ldaps://legacy:636"); got != want {
			t.Fatalf("LDAPEndpoint(%q) = %q; want %q", in, got, want)
		}
	}
}
func TestBaseDN(t *testing.T) {
	if got := BaseDN("CORP.EXAMPLE.COM"); got != "DC=CORP,DC=EXAMPLE,DC=COM" {
		t.Fatalf("BaseDN = %q", got)
	}
	if BaseDN("") != "" {
		t.Fatal("empty domain must not produce a base DN")
	}
}
func TestLoadLDAP(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "ENCRYPTION_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ=", "APP_ENV": "development"}
	load := func(extra map[string]string) (Config, error) {
		for k, v := range base {
			t.Setenv(k, v)
		}
		for _, k := range []string{"LDAP_SERVER", "LDAP_URL", "LDAP_DOMAIN", "LDAP_BASE_DN", "LDAP_BIND_DN", "LDAP_USER_FILTER", "LDAP_STARTTLS", "LDAP_ALLOW_PLAINTEXT"} {
			t.Setenv(k, "")
		}
		for k, v := range extra {
			t.Setenv(k, v)
		}
		return Load()
	}
	c, e := load(map[string]string{"LDAP_SERVER": "192.0.2.10", "LDAP_DOMAIN": "CORP.EXAMPLE.COM", "LDAP_ALLOW_PLAINTEXT": "true"})
	if e != nil {
		t.Fatal(e)
	}
	if c.LDAPURL != "ldap://192.0.2.10:389" || c.LDAPBaseDN != "DC=CORP,DC=EXAMPLE,DC=COM" || c.LDAPUserFilter != "(sAMAccountName=%s)" {
		t.Fatalf("config = %+v", c)
	}
	if _, e = load(map[string]string{"LDAP_SERVER": "192.0.2.10", "LDAP_DOMAIN": "CORP.EXAMPLE.COM", "LDAP_STARTTLS": "false"}); e == nil {
		t.Fatal("plaintext LDAP accepted without an explicit opt-in")
	}
	if _, e = load(map[string]string{"LDAP_URL": "ldaps://ad:636"}); e == nil {
		t.Fatal("LDAP accepted without a domain or a bind DN")
	}
	if _, e = load(map[string]string{"LDAP_URL": "ldaps://ad:636", "LDAP_BIND_DN": "cn=svc,dc=x", "LDAP_BASE_DN": "dc=x"}); e != nil {
		t.Fatalf("search-account mode rejected: %v", e)
	}
}
