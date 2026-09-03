package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"strings"
	"time"
)

type LDAP struct{ Config config.Config }

func (p *LDAP) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	var id Identity
	if password == "" || username == "" {
		return id, ErrCredentials
	}
	if e := ctx.Err(); e != nil {
		return id, e
	}
	c, e := ldap.DialURL(p.Config.LDAPURL, ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	if e != nil {
		return id, ErrCredentials
	}
	defer c.Close()
	c.SetTimeout(10 * time.Second)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if e = c.Bind(p.Config.LDAPBindDN, p.Config.LDAPBindPassword); e != nil {
		return id, ErrCredentials
	}
	filter := strings.ReplaceAll(p.Config.LDAPUserFilter, "%s", ldap.EscapeFilter(username))
	res, e := c.Search(ldap.NewSearchRequest(p.Config.LDAPBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, filter, []string{"uid", "sAMAccountName", "mail", p.Config.LDAPGroupAttribute}, nil))
	if e != nil || len(res.Entries) != 1 {
		return id, ErrCredentials
	}
	entry := res.Entries[0]
	if e = c.Bind(entry.DN, password); e != nil {
		return id, ErrCredentials
	}
	id = Identity{Subject: entry.DN, Username: username, Email: entry.GetAttributeValue("mail"), Groups: entry.GetAttributeValues(p.Config.LDAPGroupAttribute)}
	id.Role, e = MappedRole(p.Config.LDAPRoleMapping, id.Groups)
	return id, e
}
func MappedRole(raw string, groups []string) (string, error) {
	mapping := map[string]string{}
	if e := json.Unmarshal([]byte(raw), &mapping); e != nil {
		return "", fmt.Errorf("invalid role mapping")
	}
	priority := map[string]int{"VIEWER": 1, "AUDITOR": 2, "APPROVER": 3, "OPERATOR": 4, "ADMIN": 5}
	role := "VIEWER"
	for _, g := range groups {
		r := mapping[g]
		if priority[r] > priority[role] {
			role = r
		}
	}
	return role, nil
}
