# Security policy

This repository contains an infrastructure control plane. Do not place real credentials, kubeconfigs, SSH keys, environment files or database dumps in public issues or pull requests.

Report a suspected vulnerability privately through GitHub's private vulnerability reporting feature when available. Include affected version, sanitized reproduction steps and impact. If that feature is unavailable, request a private reporting channel without disclosing exploit details or secrets in a public issue.

Before deploying, read [deployment hardening](docs/SECURITY.md), [agent security](docs/AGENT_SECURITY.md) and the [implementation limits](docs/STATUS.md). The initial release has not undergone an independent penetration test. Dependency updates are proposed by Dependabot and must pass CI.
