package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"golang.org/x/term"
	"net/http"
	"os"
	"strings"
	"time"
)

var version = "0.1.0"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: infra-orchestrator admin create|reset-password, migrate, health, version")
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if args[0] == "health" {
		client := &http.Client{Timeout: 5 * time.Second}
		r, e := client.Get(config.Env("HEALTH_URL", "http://127.0.0.1:8080/healthz"))
		if e != nil {
			return e
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("health HTTP %d", r.StatusCode)
		}
		fmt.Println("healthy")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, e := store.Open(ctx, config.Env("DATABASE_URL", ""))
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx); e != nil {
		return e
	}
	if args[0] == "migrate" {
		fmt.Println("migrations applied")
		return nil
	}
	if len(args) < 2 || args[0] != "admin" || !domain.Contains([]string{"create", "reset-password"}, args[1]) {
		return fmt.Errorf("unknown command")
	}
	flags := flag.NewFlagSet("admin", flag.ContinueOnError)
	username := flags.String("username", "", "username")
	email := flags.String("email", "", "email address")
	stdin := flags.Bool("password-stdin", false, "read password from stdin (otherwise hidden terminal prompt)")
	if e = flags.Parse(args[2:]); e != nil {
		return e
	}
	if *username == "" {
		return fmt.Errorf("--username required")
	}
	var password string
	if *stdin {
		s := bufio.NewScanner(os.Stdin)
		if !s.Scan() {
			return fmt.Errorf("password required on stdin")
		}
		password = s.Text()
	} else {
		fmt.Fprint(os.Stderr, "Password (minimum 12 characters): ")
		b, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if e != nil {
			return e
		}
		password = string(b)
	}
	hash, e := security.HashPassword(password)
	if e != nil {
		return e
	}
	if args[1] == "create" {
		if *email == "" || !strings.Contains(*email, "@") {
			return fmt.Errorf("--email required")
		}
		u := domain.User{ID: domain.ID(), Username: *username, Email: *email, PasswordHash: hash, Role: "ADMIN", Enabled: true, Environments: []string{"*"}}
		if e = db.CreateUser(ctx, u); e != nil {
			return e
		}
		if e = db.Audit(ctx, domain.Event{Actor: "bootstrap-cli", ActorType: "cli", Action: "user.admin_created", Metadata: map[string]any{"user_id": u.ID}}); e != nil {
			return e
		}
		fmt.Println("Administrator created:", u.Username)
		return nil
	}
	u, e := db.UserLogin(ctx, *username)
	if e != nil {
		return e
	}
	tx, e := db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "UPDATE users SET password_hash=$2,force_password=true WHERE id=$1", u.ID, hash); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE sessions SET revoked_at=now() WHERE user_id=$1", u.ID); e != nil {
		return e
	}
	if e = store.AuditTx(ctx, tx, domain.Event{Actor: "bootstrap-cli", ActorType: "cli", Action: "user.password_reset", Metadata: map[string]any{"user_id": u.ID}}); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	fmt.Println("Password reset; sessions revoked.")
	return nil
}
