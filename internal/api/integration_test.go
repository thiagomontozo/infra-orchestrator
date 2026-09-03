package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/thiagomontozo/infra-orchestrator/internal/app"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRealDBAuthenticationCSRFAndBOLA(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	cfg := config.Config{Name: "test", Env: "test", SecretBackend: "local", DatabaseURL: raw, EncryptionKey: make([]byte, 32), Origin: "http://test.local", Concurrency: 2, SessionTTL: time.Hour, SSHTimeout: time.Second, CommandTimeout: time.Second}
	a, e := app.Build(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer a.DB.Pool.Close()
	password := "integration-long-passphrase"
	hash, e := security.HashPassword(password)
	if e != nil {
		t.Fatal(e)
	}
	uid := domain.ID()
	u := domain.User{ID: uid, Username: uid, Email: uid + "@example.test", PasswordHash: hash, Role: "VIEWER", Enabled: true, Environments: []string{"staging"}}
	if e = a.DB.CreateUser(ctx, u); e != nil {
		t.Fatal(e)
	}
	handler := a.API.Handler()
	request := func(method, path string, body any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Origin", cfg.Origin)
		req.Header.Set("X-CSRF-Token", csrf)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}
	login := request("POST", "/api/v1/auth/login", map[string]string{"login": u.Username, "password": password, "method": "local"}, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	var payload struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &payload)
	cookies := login.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatal("secure session cookies missing")
	}
	for _, c := range cookies {
		if c.Name == "io_session" && (!c.HttpOnly || c.SameSite != http.SameSiteStrictMode) {
			t.Fatal("cookie flags")
		}
	}
	if r := request("GET", "/api/v1/users", nil, cookies, ""); r.Code != 403 {
		t.Fatal("viewer read users", r.Code)
	}
	if r := request("POST", "/api/v1/auth/renew", nil, cookies, ""); r.Code != 401 {
		t.Fatal("CSRF bypass", r.Code)
	}
	host := domain.Host{ID: domain.ID(), Name: "production-test", Environment: "production", Enabled: true}
	if e = a.DB.SaveHost(ctx, host); e != nil {
		t.Fatal(e)
	}
	if e = a.DB.UpsertResources(ctx, host.ID, "docker", []domain.Resource{{ExternalID: "container", Name: "secret-production-resource", Type: "docker_container", Environment: "production"}}); e != nil {
		t.Fatal(e)
	}
	resources, e := a.DB.Resources(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, resource := range resources {
		if resource.HostID == host.ID {
			r := request("GET", "/api/v1/resources/"+resource.ID, nil, cookies, "")
			if r.Code != 403 {
				t.Fatal("BOLA bypass", r.Code)
			}
		}
	}
	logout := request("POST", "/api/v1/auth/logout", map[string]any{}, cookies, payload.CSRF)
	if logout.Code != 200 {
		t.Fatal(logout.Code, logout.Body.String())
	}
	if r := request("GET", "/api/v1/auth/me", nil, cookies, ""); r.Code != 401 {
		t.Fatal("revoked session accepted")
	}
}
