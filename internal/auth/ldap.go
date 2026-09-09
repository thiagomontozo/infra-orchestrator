package auth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type LDAP struct{ Config config.Config }

// ADAttributes are the directory fields read for every authenticated account.
var ADAttributes = []string{"sAMAccountName", "displayName", "mail", "objectGUID", "physicalDeliveryOfficeName", "thumbnailPhoto"}

var ldapSafe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// SanitizeLogin rejects logins carrying characters outside the account charset, preventing LDAP injection.
func SanitizeLogin(login string) (string, error) {
	if !ldapSafe.MatchString(login) {
		return "", fmt.Errorf("login contains invalid characters")
	}
	return login, nil
}

// FormatGUID renders the mixed-endian binary objectGUID of Active Directory as its canonical string form.
func FormatGUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%x-%x", raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8:10], raw[10:16])
}
func (p *LDAP) connect(ctx context.Context) (*ldap.Conn, error) {
	host := p.Config.LDAPURL
	if u, e := url.Parse(p.Config.LDAPURL); e == nil {
		host = u.Hostname()
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: p.Config.LDAPSkipVerify, RootCAs: p.Config.LDAPCAPool}
	c, e := ldap.DialURL(p.Config.LDAPURL, ldap.DialWithTLSConfig(cfg))
	if e != nil {
		return nil, e
	}
	c.SetTimeout(10 * time.Second)
	if strings.HasPrefix(p.Config.LDAPURL, "ldap://") && p.Config.LDAPStartTLS {
		if e = c.StartTLS(cfg); e != nil && !p.Config.LDAPAllowPlaintext {
			c.Close()
			return nil, e
		}
	}
	if e = ctx.Err(); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func (p *LDAP) search(c *ldap.Conn, login string) (*ldap.Entry, error) {
	filter := strings.ReplaceAll(p.Config.LDAPUserFilter, "%s", ldap.EscapeFilter(login))
	res, e := c.Search(ldap.NewSearchRequest(p.Config.LDAPBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, filter, append(append([]string{}, ADAttributes...), "uid", p.Config.LDAPGroupAttribute), nil))
	if e != nil || len(res.Entries) != 1 {
		return nil, ErrCredentials
	}
	return res.Entries[0], nil
}

// Identity maps a directory entry onto the local account model.
func (p *LDAP) Identity(entry *ldap.Entry, login string) (Identity, error) {
	id := Identity{Subject: entry.DN, Username: entry.GetAttributeValue("sAMAccountName"), Email: entry.GetAttributeValue("mail"), DisplayName: entry.GetAttributeValue("displayName"), OfficeLocation: entry.GetAttributeValue("physicalDeliveryOfficeName"), Groups: entry.GetAttributeValues(p.Config.LDAPGroupAttribute)}
	if photo := entry.GetRawAttributeValue("thumbnailPhoto"); len(photo) > 0 {
		id.Photo = base64.StdEncoding.EncodeToString(photo)
	}
	if id.Username == "" {
		id.Username = strings.TrimSpace(entry.GetAttributeValue("uid"))
	}
	if id.Username == "" {
		id.Username = login
	}
	if guid := FormatGUID(entry.GetRawAttributeValue("objectGUID")); guid != "" && p.Config.LDAPDomain != "" {
		id.Subject = guid
	}
	// The directory does not guarantee an e-mail; the local account keys on it, so derive one from the domain.
	if id.Email == "" && p.Config.LDAPDomain != "" {
		id.Email = strings.ToLower(id.Username + "@" + p.Config.LDAPDomain)
	}
	if id.DisplayName == "" {
		id.DisplayName = id.Username
	}
	var e error
	id.Role, e = MappedRole(p.Config.LDAPRoleMapping, id.Groups)
	return id, e
}

// Authenticate binds as the user themselves (Active Directory UPN) or through a search account, depending on configuration.
func (p *LDAP) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	var id Identity
	if password == "" || username == "" {
		return id, ErrCredentials
	}
	if e := ctx.Err(); e != nil {
		return id, e
	}
	login := username
	if p.Config.LDAPDomain != "" {
		var e error
		if login, e = SanitizeLogin(username); e != nil {
			return id, ErrCredentials
		}
	}
	c, e := p.connect(ctx)
	if e != nil {
		return id, ErrCredentials
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if p.Config.LDAPDomain != "" {
		if e = c.Bind(login+"@"+p.Config.LDAPDomain, password); e != nil {
			return id, ErrCredentials
		}
		entry, e := p.search(c, login)
		if e != nil {
			return id, e
		}
		return p.Identity(entry, login)
	}
	if e = c.Bind(p.Config.LDAPBindDN, p.Config.LDAPBindPassword); e != nil {
		return id, ErrCredentials
	}
	entry, e := p.search(c, login)
	if e != nil {
		return id, e
	}
	if e = c.Bind(entry.DN, password); e != nil {
		return id, ErrCredentials
	}
	return p.Identity(entry, login)
}

// MappedRole resolves the highest role the directory grants, or "" when no configured group matches.
// An empty result means the directory has no opinion, leaving the locally assigned role in place.
func MappedRole(raw string, groups []string) (string, error) {
	mapping := map[string]string{}
	if e := json.Unmarshal([]byte(raw), &mapping); e != nil {
		return "", fmt.Errorf("invalid role mapping")
	}
	priority := map[string]int{"VIEWER": 1, "AUDITOR": 2, "APPROVER": 3, "OPERATOR": 4, "ADMIN": 5}
	role := ""
	for _, g := range groups {
		r := mapping[g]
		if priority[r] > priority[role] {
			role = r
		}
	}
	return role, nil
}
