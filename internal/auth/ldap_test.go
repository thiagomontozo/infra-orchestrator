package auth

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"testing"
)

func TestSanitizeLogin(t *testing.T) {
	for _, ok := range []string{"jdoe", "jane.doe", "user_x-1", "A1"} {
		if _, e := SanitizeLogin(ok); e != nil {
			t.Fatalf("rejected valid login %q: %v", ok, e)
		}
	}
	for _, bad := range []string{"", "user@domain", "user)(uid=*", "user*", "user name", "us,er", "\\75ser"} {
		if _, e := SanitizeLogin(bad); e == nil {
			t.Fatalf("accepted injectable login %q", bad)
		}
	}
}
func TestFormatGUID(t *testing.T) {
	raw := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	if got := FormatGUID(raw); got != "12345678-9abc-def0-0123-456789abcdef" {
		t.Fatalf("guid = %q", got)
	}
	if FormatGUID(nil) != "" || FormatGUID(raw[:15]) != "" {
		t.Fatal("malformed objectGUID accepted")
	}
}
func TestIdentityFromDirectory(t *testing.T) {
	p := &LDAP{Config: config.Config{LDAPDomain: "CORP.EXAMPLE.COM", LDAPGroupAttribute: "memberOf", LDAPRoleMapping: `{"CN=Infra,DC=CORP":"OPERATOR","CN=Sec,DC=CORP":"ADMIN"}`}}
	entry := ldap.NewEntry("CN=Jane Doe,DC=CORP", map[string][]string{
		"sAMAccountName":             {"jdoe"},
		"displayName":                {"Jane Doe"},
		"mail":                       {"jdoe@example.com"},
		"physicalDeliveryOfficeName": {"Headquarters"},
		"objectGUID":                 {string([]byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})},
		"thumbnailPhoto":             {"\xff\xd8\xff"},
		"memberOf":                   {"CN=Infra,DC=CORP", "CN=Sec,DC=CORP"},
	})
	id, e := p.Identity(entry, "jdoe")
	if e != nil {
		t.Fatal(e)
	}
	if id.Subject != "12345678-9abc-def0-0123-456789abcdef" {
		t.Fatalf("subject = %q; want the objectGUID", id.Subject)
	}
	if id.Username != "jdoe" || id.DisplayName != "Jane Doe" || id.OfficeLocation != "Headquarters" || id.Email != "jdoe@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	if id.Photo != "/9j/" {
		t.Fatalf("photo = %q; want base64 of the thumbnail", id.Photo)
	}
	if id.Role != "ADMIN" {
		t.Fatalf("role = %q; want the highest mapped group", id.Role)
	}
}
func TestIdentityWithoutMailOrGuid(t *testing.T) {
	p := &LDAP{Config: config.Config{LDAPDomain: "CORP.EXAMPLE.COM", LDAPGroupAttribute: "memberOf", LDAPRoleMapping: "{}"}}
	entry := ldap.NewEntry("CN=Sem Mail,DC=CORP", map[string][]string{"sAMAccountName": {"SemMail"}})
	id, e := p.Identity(entry, "semmail")
	if e != nil {
		t.Fatal(e)
	}
	if id.Email != "semmail@corp.example.com" {
		t.Fatalf("email = %q; want one derived from the domain", id.Email)
	}
	if id.Subject != "CN=Sem Mail,DC=CORP" {
		t.Fatalf("subject = %q; want the DN when objectGUID is absent", id.Subject)
	}
	if id.DisplayName != "SemMail" || id.Role != "" {
		t.Fatalf("identity = %+v", id)
	}
}
func TestMappedRole(t *testing.T) {
	if _, e := MappedRole("not json", nil); e == nil {
		t.Fatal("invalid mapping accepted")
	}
	r, e := MappedRole(`{"g":"AUDITOR"}`, []string{"unknown"})
	if e != nil || r != "" {
		t.Fatalf("role = %q, %v; want no directory opinion", r, e)
	}
	if r, e = MappedRole(`{"g":"AUDITOR","h":"OPERATOR"}`, []string{"g", "h"}); e != nil || r != "OPERATOR" {
		t.Fatalf("role = %q, %v; want the highest match", r, e)
	}
}
