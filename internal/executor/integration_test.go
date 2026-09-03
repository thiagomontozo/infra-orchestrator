package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type keyProvider []byte

func (k keyProvider) Get(context.Context, string) ([]byte, error) { return k, nil }
func (k keyProvider) Put(context.Context, string, []byte) error   { return nil }
func (k keyProvider) Delete(context.Context, string) error        { return nil }
func TestVerifiedSSHActualProtocol(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(priv)
	if e != nil {
		t.Fatal(e)
	}
	authPub, e := ssh.NewPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	hostKey, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = hostKey
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(authPub.Marshal()) {
			return nil, fmt.Errorf("unauthorized")
		}
		return nil, nil
	}}
	cfg.AddHostKey(hostSigner)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				conn, channels, requests, e := ssh.NewServerConn(raw, cfg)
				if e != nil {
					raw.Close()
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for ch := range channels {
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, reqs, e := ch.Accept()
					if e != nil {
						continue
					}
					for req := range reqs {
						if req.Type == "exec" {
							var payload struct{ Command string }
							_ = ssh.Unmarshal(req.Payload, &payload)
							if payload.Command != "hostname '-f'" {
								req.Reply(false, nil)
								channel.Close()
								continue
							}
							req.Reply(true, nil)
							io.WriteString(channel, "ssh-fixture.local\n")
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							channel.Close()
							break
						}
					}
				}
			}()
		}
	}()
	network, _ := security.NewNetworkPolicy([]string{"127.0.0.0/8"})
	rawKey, e := ssh.MarshalPrivateKey(priv, "test")
	if e != nil {
		t.Fatal(e)
	}
	_ = rawKey // Use a real agent socket is not necessary; config signer is verified below.
	clientCfg := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(hostSigner.PublicKey()) {
			return fmt.Errorf("wrong fingerprint")
		}
		return nil
	}, Timeout: time.Second}
	raw, e := network.DialContext(ctx, "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	sc, ch, req, e := ssh.NewClientConn(raw, listener.Addr().String(), clientCfg)
	if e != nil {
		t.Fatal(e)
	}
	client := ssh.NewClient(sc, ch, req)
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	b, e := session.Output("hostname '-f'")
	if e != nil || string(b) != "ssh-fixture.local\n" {
		t.Fatal(string(b), e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	remote := &SSH{Network: network, ConnectTimeout: time.Second}
	fingerprint, e := remote.Probe(ctx, domain.Host{Hostname: "127.0.0.1", Port: port, Username: "test"})
	if e != nil || fingerprint != ssh.FingerprintSHA256(hostSigner.PublicKey()) {
		t.Fatal("probe failed", e)
	}
}
func TestRemoteDockerSSH(t *testing.T) {
	if os.Getenv("TEST_SSH_KEY") == "" {
		t.Skip("TEST_SSH_KEY required for Docker SSH fixture")
	}
	b, e := os.ReadFile(os.Getenv("TEST_SSH_KEY"))
	if e != nil {
		t.Fatal(e)
	}
	network, _ := security.NewNetworkPolicy([]string{"127.0.0.0/8"})
	remote := &SSH{Secrets: keyProvider(b), Network: network, ConnectTimeout: 10 * time.Second, CommandTimeout: 30 * time.Second, Slots: make(chan struct{}, 2)}
	h := domain.Host{ID: "fixture", Hostname: "127.0.0.1", Port: 55222, Username: "operator", AuthMethod: "key", SecretID: "test", Enabled: true}
	fp, e := remote.Probe(context.Background(), h)
	if e != nil {
		t.Fatal(e)
	}
	h.Fingerprint = fp
	out, e := remote.Run(context.Background(), h, Command{Program: "docker", Args: []string{"info", "--format", "{{.ServerVersion}}"}})
	if e != nil {
		t.Fatal(e, out.Output)
	}
	if out.Output == "" {
		t.Fatal("Docker unavailable")
	}
	h.Fingerprint = "SHA256:wrong"
	if _, e = remote.Run(context.Background(), h, Command{Program: "hostname"}); e == nil {
		t.Fatal("fingerprint mismatch accepted")
	}
}
