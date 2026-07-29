# cert-rotator

A production-grade, pure Go application for automated rotation of Kubernetes control plane certificates in self-hosted clusters.

## Why cert-rotator?

Kubernetes control plane certificates issued by kubeadm have a default validity of one year. There is no native automated solution for rotating these certificates in self-hosted clusters:

- `kubeadm certs renew` — manual CLI command, no automation
- `--rotate-certificates` — only covers kubelet certs, not control plane certs
- `cert-manager` — works with Kubernetes Secrets, not kubeadm PKI on disk
- Cron scripts — no HA awareness, no rollback, no state management

cert-rotator fills this gap with a purpose-built Go application that owns the complete certificate lifecycle.

## Features

- **Pure Go** — no kubeadm, no external runtime dependencies
- **Automated detection** — reads cert expiry directly from `/etc/kubernetes/pki/` using `crypto/x509`
- **Automated renewal** — generates new certs using Go's crypto stdlib, signs with existing CA key material
- **Pre-renewal cert backup** — file-level backup of all cert and kubeconfig files before any write
- **Automated full-cluster rollback** — on any failure, all renewed nodes are rolled back in reverse order
- **HA aware** — one node at a time with health check gates between each node
- **Crash recovery** — state persisted to `state.json`, resumes in-progress rollback on restart
- **Airgapped safe** — zero internet dependency, works in fully airgapped environments
- **Notifications** — SMTP and Slack webhook for all events including P0 critical alerts
- **Dry run mode** — validate what would happen without executing

## Certificates managed

| Certificate | CA | Type |
|---|---|---|
| apiserver | ca | serving |
| apiserver-etcd-client | etcd-ca | client |
| apiserver-kubelet-client | ca | client |
| etcd-server | etcd-ca | serving |
| etcd-peer | etcd-ca | serving/client |
| etcd-healthcheck-client | etcd-ca | client |
| front-proxy-client | front-proxy-ca | client |
| admin.conf | ca | kubeconfig |
| controller-manager.conf | ca | kubeconfig |
| scheduler.conf | ca | kubeconfig |
| super-admin.conf | ca | kubeconfig |

CA certificates (`ca`, `etcd-ca`, `front-proxy-ca`) are explicitly excluded — 10-year validity, separate rotation procedure required.

## How it works
Reconciliation loop (every 24h)
↓
Read certs from /etc/kubernetes/pki/ via crypto/x509
↓
Classify: ok / approaching (≤30d) / expired (urgent)
↓
For each control plane node (one at a time):

Cert backup — copy pki/ and kubeconfigs to timestamped dir
Persist backup path to state.json
Generate new RSA 2048 key
Build x509 template — mirror SANs and key usages exactly
Sign with correct CA key (etcd-ca / front-proxy-ca / ca)
Write new cert + key files
Regenerate kubeconfig files
Restart static pods: etcd → apiserver → controller-manager → scheduler
Health check all components
On failure → rollback all renewed nodes in reverse order

## Rollback strategy

On any failure — write error, pod restart failure, or health check failure — cert-rotator performs a full cluster rollback:

- All nodes that were renewed are rolled back in reverse order
- Rollback restores cert backup, restarts static pods with old certs, and health checks each node
- If rollback itself fails: a P0 critical alert fires unconditionally via both SMTP and Slack
- State is persisted throughout — if cert-rotator crashes mid-rollback, it resumes on restart

## Package structure
cert-rotator/
├── cmd/main.go              # entry point, reconciliation loop
├── pkg/
│   ├── detector/            # cert expiry detection via crypto/x509
│   ├── generator/           # RSA key generation, x509 template builder
│   ├── signer/              # CA signing with correct CA routing per cert
│   ├── backup/              # file-level cert backup and restore
│   ├── writer/              # PEM file writer with correct permissions
│   ├── kubeconfig/          # kubeconfig regeneration
│   ├── podrestart/          # static pod manifest cycling
│   ├── healthcheck/         # TCP + HTTPS health probes
│   ├── rollback/            # full cluster rollback orchestration
│   └── notifier/            # SMTP + Slack webhook notifications
├── config/config.go         # configuration
└── state/state.go           # state persistence and crash recovery

## Configuration

| Parameter | Default | Description |
|---|---|---|
| `renewal_threshold_days` | `30` | Days before expiry to trigger renewal |
| `check_interval_hours` | `24` | How often the reconciliation loop runs |
| `backup_dir` | `/var/lib/cert-rotator/backups/` | Where cert backups are stored |
| `state_file` | `/var/lib/cert-rotator/state.json` | Persisted state path |
| `dry_run` | `false` | Log what would happen without executing |
| `smtp_enabled` | `false` | Enable SMTP notifications |
| `slack_webhook_enabled` | `false` | Enable Slack webhook notifications |

## Building
```bash
go build ./...
```

## Testing
```bash
go test ./...
```

## State machine
IDLE → DETECTING → RENEWING_N1 → RENEWING_N2 → RENEWING_N3 → NOTIFYING → IDLE
↓               ↓               ↓
ROLLBACK_N1    ROLLBACK_N2    ROLLBACK_N3
↑               ↑               ↑
(reverse order on any failure)

State is persisted to `state.json` after every transition. On restart, cert-rotator reads state and completes any in-progress rollback before entering IDLE.

## Requirements

- Go 1.21+
- Access to `/etc/kubernetes/pki/` on each control plane node
- Port 443 connectivity between controller and control plane nodes
- CA key material present at standard kubeadm paths

## License

Apache 2.0
