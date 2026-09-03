package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"
)

type OIDC struct {
	Auth     *Service
	Provider *oidc.Provider
	OAuth    oauth2.Config
	Verifier *oidc.IDTokenVerifier
}

func NewOIDC(ctx context.Context, s *Service) (*OIDC, error) {
	c := s.Config
	p, e := oidc.NewProvider(ctx, c.OIDCIssuer)
	if e != nil {
		return nil, e
	}
	return &OIDC{Auth: s, Provider: p, OAuth: oauth2.Config{ClientID: c.OIDCClientID, ClientSecret: c.OIDCClientSecret, RedirectURL: c.OIDCRedirect, Endpoint: p.Endpoint(), Scopes: strings.Fields(c.OIDCScopes)}, Verifier: p.Verifier(&oidc.Config{ClientID: c.OIDCClientID})}, nil
}
func (o *OIDC) Start(w http.ResponseWriter, r *http.Request) {
	state, nonce, verifier := security.Random(32), security.Random(32), oauth2.GenerateVerifier()
	_, e := o.Auth.DB.Pool.Exec(r.Context(), "INSERT INTO oidc_states(hash,nonce,verifier,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')", security.HashToken(state), nonce, verifier)
	if e != nil {
		http.Error(w, "SSO unavailable", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "io_oidc", Value: state, Path: "/api/v1/auth/oidc/", HttpOnly: true, Secure: o.Auth.Config.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	http.Redirect(w, r, o.OAuth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}
func (o *OIDC) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookie, e := r.Cookie("io_oidc")
	if e != nil || cookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid SSO state", 400)
		return
	}
	var nonce, verifier string
	e = o.Auth.DB.Pool.QueryRow(ctx, "DELETE FROM oidc_states WHERE hash=$1 AND expires_at>now() RETURNING nonce,verifier", security.HashToken(cookie.Value)).Scan(&nonce, &verifier)
	if e != nil {
		http.Error(w, "expired SSO state", 400)
		return
	}
	token, e := o.OAuth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if e != nil {
		http.Error(w, "SSO exchange failed", 401)
		return
	}
	raw, _ := token.Extra("id_token").(string)
	t, e := o.Verifier.Verify(ctx, raw)
	if e != nil || t.Nonce != nonce {
		http.Error(w, "invalid identity token", 401)
		return
	}
	var claims map[string]json.RawMessage
	if e = t.Claims(&claims); e != nil {
		http.Error(w, "invalid claims", 401)
		return
	}
	var email string
	var verified bool
	var groups []string
	_ = json.Unmarshal(claims["email"], &email)
	_ = json.Unmarshal(claims["email_verified"], &verified)
	_ = json.Unmarshal(claims[o.Auth.Config.OIDCGroupClaim], &groups)
	if !verified {
		http.Error(w, "verified email required", 403)
		return
	}
	role, e := MappedRole(o.Auth.Config.OIDCRoleMapping, groups)
	if e != nil {
		http.Error(w, "invalid role mapping", 503)
		return
	}
	u, e := o.Auth.SyncIdentity(ctx, "oidc", Identity{Subject: t.Issuer + "|" + t.Subject, Username: email, Email: email, Role: role, Groups: groups})
	if e != nil || !u.Enabled {
		http.Error(w, "SSO user denied", 403)
		return
	}
	if u.MFAEnabled || u.MFARequired {
		http.Error(w, "This account requires local TOTP; use local authentication or enroll an IdP-only account with enforced upstream MFA.", 403)
		return
	}
	if _, e = o.Auth.CreateSession(ctx, w, r, u, false, "oidc"); e != nil {
		http.Error(w, "session failed", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "io_oidc", Value: "", Path: "/api/v1/auth/oidc/", MaxAge: -1, HttpOnly: true, Secure: o.Auth.Config.SecureCookies, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

var _ = fmt.Sprint
var _ = time.Now
