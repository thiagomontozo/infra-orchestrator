package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Provider interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}
type Local struct {
	DB     *store.DB
	Cipher *security.Cipher
}

func (p *Local) Put(ctx context.Context, id string, value []byte) error {
	c, e := p.Cipher.Encrypt(id, value)
	if e != nil {
		return e
	}
	_, e = p.DB.Pool.Exec(ctx, "INSERT INTO secrets(id,ciphertext) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET ciphertext=$2", id, c)
	return e
}
func (p *Local) Get(ctx context.Context, id string) ([]byte, error) {
	var c string
	e := p.DB.Pool.QueryRow(ctx, "SELECT ciphertext FROM secrets WHERE id=$1", id).Scan(&c)
	if e != nil {
		return nil, e
	}
	return p.Cipher.Decrypt(id, c)
}
func (p *Local) Delete(ctx context.Context, id string) error {
	_, e := p.DB.Pool.Exec(ctx, "DELETE FROM secrets WHERE id=$1", id)
	return e
}

type Vault struct {
	URL, Token, Mount string
	Client            *http.Client
}

func (p *Vault) request(ctx context.Context, method, id string, body any) ([]byte, error) {
	if strings.ContainsAny(id, "/\\.") {
		return nil, fmt.Errorf("invalid secret id")
	}
	var buf bytes.Buffer
	if body != nil {
		if e := json.NewEncoder(&buf).Encode(body); e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.URL, "/")+"/v1/"+url.PathEscape(p.Mount)+"/data/"+url.PathEscape(id), &buf)
	if e != nil {
		return nil, e
	}
	req.Header.Set("X-Vault-Token", p.Token)
	req.Header.Set("Content-Type", "application/json")
	res, e := p.Client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
	if e != nil {
		return nil, e
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("Vault returned HTTP %d", res.StatusCode)
	}
	return b, nil
}
func (p *Vault) Put(ctx context.Context, id string, b []byte) error {
	_, e := p.request(ctx, http.MethodPost, id, map[string]any{"data": map[string]string{"value": string(b)}})
	return e
}
func (p *Vault) Get(ctx context.Context, id string) ([]byte, error) {
	b, e := p.request(ctx, http.MethodGet, id, nil)
	if e != nil {
		return nil, e
	}
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if e = json.Unmarshal(b, &out); e != nil {
		return nil, e
	}
	s, ok := out.Data.Data["value"]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	return []byte(s), nil
}
func (p *Vault) Delete(ctx context.Context, id string) error {
	_, e := p.request(ctx, http.MethodDelete, id, nil)
	return e
}
