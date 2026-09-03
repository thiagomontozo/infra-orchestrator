package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

type Notification struct {
	ID          string `json:"id"`
	Event       string `json:"event"`
	Environment string `json:"environment"`
	Message     string `json:"message"`
}
type Provider interface {
	Send(context.Context, Notification) error
}
type Webhook struct {
	URL, Token, Kind string
	Client           *http.Client
}

func (p *Webhook) Send(ctx context.Context, n Notification) error {
	var body any = n
	if p.Kind == "slack" || p.Kind == "teams" {
		body = map[string]string{"text": n.Event + ": " + n.Message}
	}
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", p.URL, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", n.ID)
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	res, e := p.Client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("notification endpoint HTTP %d", res.StatusCode)
	}
	return nil
}

type Email struct {
	Host, Port, Username, Password, From, To string
	Network                                  *security.NetworkPolicy
}

func (p *Email) Send(ctx context.Context, n Notification) error {
	from, e := mail.ParseAddress(p.From)
	if e != nil {
		return e
	}
	to, e := mail.ParseAddress(p.To)
	if e != nil {
		return e
	}
	conn, e := p.Network.DialContext(ctx, "tcp", net.JoinHostPort(p.Host, p.Port))
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	client, e := smtp.NewClient(conn, p.Host)
	if e != nil {
		return e
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("SMTP STARTTLS required")
	}
	if e = client.StartTLS(&tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12}); e != nil {
		return e
	}
	if p.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", p.Username, p.Password, p.Host)); e != nil {
			return e
		}
	}
	if e = client.Mail(from.Address); e != nil {
		return e
	}
	if e = client.Rcpt(to.Address); e != nil {
		return e
	}
	writer, e := client.Data()
	if e != nil {
		return e
	}
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(n.Event)
	_, e = fmt.Fprintf(writer, "From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", from.Address, to.Address, subject, security.Redact(n.Message))
	if e != nil {
		return e
	}
	if e = writer.Close(); e != nil {
		return e
	}
	return client.Quit()
}
