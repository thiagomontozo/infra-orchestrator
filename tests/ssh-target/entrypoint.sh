#!/bin/sh
set -eu
cp /test-keys/authorized_keys /home/operator/.ssh/authorized_keys
chown -R operator:operator /home/operator/.ssh
chmod 700 /home/operator/.ssh
chmod 600 /home/operator/.ssh/authorized_keys
cat > /etc/ssh/sshd_config <<'CONFIG'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PubkeyAuthentication yes
AllowUsers operator
AllowStreamLocalForwarding yes
AllowTcpForwarding yes
CONFIG
export DOCKER_TLS_CERTDIR=
# This fixture owns its daemon and /var/run; discard the PID left by container restart.
rm -f /var/run/docker.pid /var/run/docker.sock
dockerd-entrypoint.sh dockerd --host=unix:///var/run/docker.sock --group=docker > /var/log/dockerd-test.log 2>&1 &
for i in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null 2>&1 || { cat /var/log/dockerd-test.log; exit 1; }
exec /usr/sbin/sshd -D -e
