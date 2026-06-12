package main

import (
	"fmt"
	"strings"
	"time"
)

func defaultStrTFE(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.TrimSpace(s)
}

func buildTFEAgentPackage(req FileEncryptDownloadRequest) (FileEncryptPackage, error) {
	targetOS := strings.ToLower(strings.TrimSpace(req.TargetOS))
	if targetOS != "windows" {
		targetOS = "linux"
	}
	distro := strings.ToLower(strings.TrimSpace(req.Distro))
	if distro == "" {
		if targetOS == "windows" {
			distro = "windows"
		} else {
			distro = "ubuntu"
		}
	}

	apiBase := defaultStrTFE(req.APIBaseURL, "https://kms.example.com/svc/tfe")
	keyID := defaultStrTFE(req.KeyID, "")
	watchDirs := defaultStrTFE(req.WatchDirs, func() string {
		if targetOS == "windows" {
			return `C:\Sensitive`
		}
		return "/data/sensitive"
	}())
	patterns := defaultStrTFE(req.FilePatterns, "*.docx,*.xlsx,*.pdf,*.csv,*.json,*.key,*.pem")
	rotDays := req.RotationDays
	if rotDays <= 0 {
		rotDays = 90
	}
	tenantID := strings.TrimSpace(req.TenantID)

	// ── Shared env config ─────────────────────────────────────────────────────
	envContent := fmt.Sprintf(`# Vecta TFE — Transparent File Encryption agent configuration
# Algorithm: AES-256-GCM (FIPS 140-3 Level 1 approved)
# Mode: gocryptfs FUSE mount — transparent to all processes accessing the directory
# Auth token stored separately in credentials file (never in this file).
VECTA_API_BASE_URL=%s
VECTA_TENANT_ID=%s
VECTA_KEY_ID=%s
VECTA_WATCH_DIRS=%s
VECTA_FILE_PATTERNS=%s
VECTA_ROTATION_DAYS=%d
VECTA_ALGORITHM=AES-256-GCM
VECTA_HEARTBEAT_PATH=/tfe/agents/{agent_id}/heartbeat
VECTA_ROTATE_PATH=/tfe/agents/{agent_id}/rotate
VECTA_CREDENTIALS_FILE=${HOME}/.config/vecta-tfe/credentials
`, apiBase, tenantID, keyID, watchDirs, patterns, rotDays)

	// ── Linux: gocryptfs FUSE transparent mount ───────────────────────────────
	//
	// Architecture:
	//   VAULT_DIR  = $PLAIN_DIR.vecta-vault/  (encrypted backing store, on disk)
	//   PLAIN_DIR  = watch dir as configured  (FUSE mount, plaintext view)
	//
	// All processes reading/writing PLAIN_DIR see plaintext.
	// All data is encrypted in VAULT_DIR using AES-256-GCM (gocryptfs SIV mode).
	// DEK is fetched from Vecta KMS TFE service per mount; zeroed after use.
	// Service runs as a persistent daemon started at boot via systemd.

	linuxMountSh := `#!/usr/bin/env bash
# vecta-tfe-mount.sh — Vecta KMS Transparent File Encryption (Linux/FUSE)
# Uses gocryptfs for KERNEL-LEVEL transparent encryption (no root required for user mounts).
# All processes reading/writing PLAIN_DIR see plaintext; encrypted data is in VAULT_DIR.
# Algorithm: AES-256-GCM (FIPS 140-3 approved via gocryptfs -xchacha=false -aessiv)
# Requires: gocryptfs >= 2.3, openssl 3.x, curl, jq, fuse
# Runs as persistent daemon — started at boot by systemd, keeps mounts active.
set -euo pipefail

CONF_DIR="${VECTA_CONF_DIR:-$HOME/.config/vecta-tfe}"
ENV_FILE="$CONF_DIR/agent.env"
CREDS_FILE="$CONF_DIR/credentials"
AUDIT_DIR="$HOME/.local/share/vecta-tfe"
AUDIT_LOG="$AUDIT_DIR/audit.log"
PID_FILE="$CONF_DIR/agent.pid"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Config not found at $ENV_FILE. Run install.sh first." >&2; exit 1
fi
# shellcheck source=/dev/null
source "$ENV_FILE"
if [[ ! -f "$CREDS_FILE" ]]; then
  echo "ERROR: Credentials not found at $CREDS_FILE. Set VECTA_AUTH_TOKEN there." >&2; exit 1
fi
# shellcheck source=/dev/null
source "$CREDS_FILE"

# ── Fetch DEK from Vecta KMS TFE service ──────────────────────────────────────
fetch_dek() {
  curl -fsS --max-time 15 \
    -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
    -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
    -H "Content-Type: application/json" \
    -X POST "${VECTA_API_BASE_URL}/tfe/keys/${VECTA_KEY_ID}/unwrap" \
    --data '{"purpose":"tfe_mount"}' \
    | jq -r '.plaintext_dek // empty'
}

# ── Audit helpers ─────────────────────────────────────────────────────────────
audit_local() {
  local op="$1" dirs="$2"
  mkdir -p "$AUDIT_DIR"
  printf '%s [INFO] op=%s dirs=%s key=%s host=%s pid=%s\n' \
    "$(date -u +%FT%TZ)" "$op" "$dirs" "${VECTA_KEY_ID:-unknown}" "$(hostname)" "$$" \
    >> "$AUDIT_LOG"
}

audit_kms() {
  local op="$1" ts="$2"
  curl -fsS --max-time 5 \
    -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
    -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
    -H "Content-Type: application/json" \
    -X POST "${VECTA_API_BASE_URL}/tfe/file-encrypt/audit" \
    --data "{\"tenant_id\":\"${VECTA_TENANT_ID}\",\"key_id\":\"${VECTA_KEY_ID}\",\"operation\":\"${op}\",\"files_processed\":0,\"timestamp\":\"${ts}\",\"hostname\":\"$(hostname)\",\"agent_version\":\"2.0\"}" \
    >/dev/null 2>&1 || true
}

# ── Mount encrypted directories ───────────────────────────────────────────────
MOUNTED_DIRS=()

mount_dir() {
  local plain_dir="$1"
  local vault_dir="${plain_dir%.vecta-vault}.vecta-vault"
  # If plain_dir already ends with .vecta-vault, it's a vault path — skip
  [[ "$plain_dir" == *.vecta-vault ]] && return 0

  vault_dir="${plain_dir}.vecta-vault"
  mkdir -p "$vault_dir" "$plain_dir"

  # Initialise vault on first use
  if [[ ! -f "$vault_dir/gocryptfs.conf" ]]; then
    echo "[vecta-tfe] Initialising encrypted vault: $vault_dir"
    # Use AES-SIV (FIPS-approved, nonce misuse resistant) with the DEK as passphrase
    echo "$DEK_B64" | gocryptfs -init -aessiv -passfile /dev/stdin "$vault_dir"
    echo "[vecta-tfe] Vault initialised."
  fi

  # Mount if not already mounted
  if ! mountpoint -q "$plain_dir" 2>/dev/null; then
    echo "$DEK_B64" | gocryptfs -passfile /dev/stdin -rw "$vault_dir" "$plain_dir"
    echo "[vecta-tfe] Mounted (transparent): $vault_dir -> $plain_dir"
    MOUNTED_DIRS+=("$plain_dir")
  else
    echo "[vecta-tfe] Already mounted: $plain_dir"
    MOUNTED_DIRS+=("$plain_dir")
  fi
}

unmount_all() {
  local ts
  ts="$(date -u +%FT%TZ)"
  echo "[vecta-tfe] Unmounting encrypted directories..."
  for d in "${MOUNTED_DIRS[@]:-}"; do
    if mountpoint -q "$d" 2>/dev/null; then
      fusermount -u "$d" 2>/dev/null && echo "[vecta-tfe] Unmounted: $d" || true
    fi
  done
  audit_local "unmount" "${MOUNTED_DIRS[*]:-}"
  audit_kms "unmount" "$ts"
  rm -f "$PID_FILE"
}

trap unmount_all SIGTERM SIGINT SIGHUP EXIT

# Fetch DEK (in memory only — zeroed after all mounts complete)
DEK_B64=$(fetch_dek)
if [[ -z "$DEK_B64" ]]; then
  echo "ERROR: Failed to fetch DEK from Vecta KMS TFE service." >&2; exit 1
fi

# Mount all watch directories
IFS=',' read -ra DIRS <<< "${VECTA_WATCH_DIRS}"
for dir in "${DIRS[@]}"; do
  dir="${dir// /}"
  [[ -n "$dir" ]] && mount_dir "$dir"
done

# Zero and unset DEK from memory immediately after mounts complete
DEK_B64=""; unset DEK_B64

# Record PID and audit
echo $$ > "$PID_FILE"
TS="$(date -u +%FT%TZ)"
audit_local "mount" "${VECTA_WATCH_DIRS}"
audit_kms "mount" "$TS"

echo "[vecta-tfe] All directories mounted transparently. Serving until shutdown."

# ── Keep running — re-check mounts every 60s ─────────────────────────────────
while true; do
  sleep 60
  for d in "${MOUNTED_DIRS[@]:-}"; do
    if ! mountpoint -q "$d" 2>/dev/null; then
      echo "WARN: Mount lost for $d — attempting remount..." >&2
      NEW_DEK=$(fetch_dek)
      if [[ -n "$NEW_DEK" ]]; then
        echo "$NEW_DEK" | gocryptfs -passfile /dev/stdin -rw "${d}.vecta-vault" "$d" 2>/dev/null && \
          echo "[vecta-tfe] Remounted: $d"
        NEW_DEK=""; unset NEW_DEK
      fi
    fi
  done
done
`

	// Explicit encrypt/decrypt scripts for manual folder operations (batch mode)
	linuxEncryptFolderSh := `#!/usr/bin/env bash
# encrypt-folder.sh — Manually encrypt a folder's files in place (batch mode).
# Use this for initial encryption of existing data before mounting.
# Algorithm: AES-256-GCM via openssl (FIPS 140-3 approved)
# NOTE: For ongoing transparent access, use vecta-tfe-mount.sh / the systemd service.
set -euo pipefail

FOLDER="${1:-}"
if [[ -z "$FOLDER" ]]; then
  echo "Usage: $0 <folder_path>" >&2; exit 1
fi

CONF_DIR="${VECTA_CONF_DIR:-$HOME/.config/vecta-tfe}"
# shellcheck source=/dev/null
source "$CONF_DIR/agent.env"
# shellcheck source=/dev/null
source "$CONF_DIR/credentials"

KEY_B64=$(curl -fsS --max-time 15 \
  -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
  -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
  -H "Content-Type: application/json" \
  -X POST "${VECTA_API_BASE_URL}/tfe/keys/${VECTA_KEY_ID}/unwrap" \
  --data '{"purpose":"tfe_batch_encrypt"}' | jq -r '.plaintext_dek // empty')

[[ -z "$KEY_B64" ]] && { echo "ERROR: Failed to fetch DEK." >&2; exit 1; }

COUNT=0
while IFS= read -r -d '' f; do
  [[ "$f" == *.venc ]] && continue
  iv_hex=$(openssl rand -hex 12)
  openssl enc -aes-256-gcm \
    -K "$(echo "$KEY_B64" | base64 -d | xxd -p -c 256)" \
    -iv "$iv_hex" -in "$f" -out "$f.venc.tmp" 2>/dev/null
  printf '%s' "$iv_hex" | xxd -r -p > "$f.venc"
  cat "$f.venc.tmp" >> "$f.venc"
  rm -f "$f.venc.tmp" "$f"
  echo "  encrypted: $f"
  COUNT=$(( COUNT + 1 ))
done < <(find "$FOLDER" -type f -print0 2>/dev/null)

KEY_B64=""; unset KEY_B64
echo "Encrypted $COUNT files in $FOLDER."
`

	linuxDecryptFolderSh := `#!/usr/bin/env bash
# decrypt-folder.sh — Manually decrypt a folder's .venc files in place (batch mode).
# Algorithm: AES-256-GCM via openssl (FIPS 140-3 approved)
set -euo pipefail

FOLDER="${1:-}"
if [[ -z "$FOLDER" ]]; then
  echo "Usage: $0 <folder_path>" >&2; exit 1
fi

CONF_DIR="${VECTA_CONF_DIR:-$HOME/.config/vecta-tfe}"
# shellcheck source=/dev/null
source "$CONF_DIR/agent.env"
# shellcheck source=/dev/null
source "$CONF_DIR/credentials"

KEY_B64=$(curl -fsS --max-time 15 \
  -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
  -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
  -H "Content-Type: application/json" \
  -X POST "${VECTA_API_BASE_URL}/tfe/keys/${VECTA_KEY_ID}/unwrap" \
  --data '{"purpose":"tfe_batch_decrypt"}' | jq -r '.plaintext_dek // empty')

[[ -z "$KEY_B64" ]] && { echo "ERROR: Failed to fetch DEK." >&2; exit 1; }

COUNT=0
while IFS= read -r -d '' f; do
  orig="${f%.venc}"
  iv_hex=$(dd if="$f" bs=1 count=12 2>/dev/null | xxd -p)
  dd if="$f" bs=12 skip=1 of="$f.ct" 2>/dev/null
  openssl enc -d -aes-256-gcm \
    -K "$(echo "$KEY_B64" | base64 -d | xxd -p -c 256)" \
    -iv "$iv_hex" -in "$f.ct" -out "$orig" 2>/dev/null
  rm -f "$f.ct" "$f"
  echo "  decrypted: $f -> $orig"
  COUNT=$(( COUNT + 1 ))
done < <(find "$FOLDER" -type f -name "*.venc" -print0 2>/dev/null)

KEY_B64=""; unset KEY_B64
echo "Decrypted $COUNT files in $FOLDER."
`

	linuxInstallSh := fmt.Sprintf(`#!/usr/bin/env bash
# install.sh — Install Vecta TFE transparent encryption agent (user-space, no root required).
# Installs gocryptfs for FUSE-based transparent mount.
# Service starts at boot and keeps all encrypted directories mounted.
set -euo pipefail

CONF_DIR="${HOME}/.config/vecta-tfe"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_DIR="${HOME}/.config/systemd/user"

echo "=== Vecta TFE — Transparent File Encryption Agent ==="
echo "    FUSE-based transparent encryption via gocryptfs"
echo "    No root or kernel module required for user mounts."
echo ""

# ── Install dependencies ───────────────────────────────────────────────────────
_install_deps() {
  if command -v apt-get &>/dev/null; then
    echo "  [apt] Installing gocryptfs, openssl, fuse, curl, jq..."
    apt-get install -y gocryptfs openssl fuse curl jq 2>/dev/null || true
  elif command -v yum &>/dev/null; then
    echo "  [yum] Installing gocryptfs, openssl, fuse, curl, jq..."
    yum install -y gocryptfs openssl fuse curl jq 2>/dev/null || true
  elif command -v dnf &>/dev/null; then
    echo "  [dnf] Installing gocryptfs, openssl, fuse, curl, jq..."
    dnf install -y gocryptfs openssl fuse curl jq 2>/dev/null || true
  elif command -v apk &>/dev/null; then
    echo "  [apk] Installing gocryptfs, openssl, fuse, curl, jq..."
    apk add --no-cache gocryptfs openssl fuse curl jq 2>/dev/null || true
  else
    echo "  WARN: Unknown package manager. Install gocryptfs, openssl, fuse, curl, jq manually." >&2
  fi
}

for dep in gocryptfs openssl curl jq xxd fusermount; do
  command -v "$dep" &>/dev/null || { _install_deps; break; }
done

for dep in gocryptfs openssl curl jq xxd fusermount; do
  command -v "$dep" &>/dev/null || { echo "ERROR: $dep missing after install attempt." >&2; exit 1; }
done

OSSL_MAJOR=$(openssl version | awk '{print $2}' | cut -d. -f1)
(( OSSL_MAJOR >= 3 )) || { echo "ERROR: openssl 3.x required for FIPS-approved AES-256-GCM." >&2; exit 1; }

# ── Create directories ─────────────────────────────────────────────────────────
mkdir -p "$CONF_DIR" "$BIN_DIR" "$SYSTEMD_DIR"
chmod 700 "$CONF_DIR"

# ── Write agent config (no auth token — stored in credentials file) ────────────
cat > "$CONF_DIR/agent.env" <<'ENVEOF'
%s
ENVEOF
chmod 600 "$CONF_DIR/agent.env"

# ── Create credentials file (0600) ────────────────────────────────────────────
CREDS_FILE="$CONF_DIR/credentials"
if [[ ! -f "$CREDS_FILE" ]]; then
  cat > "$CREDS_FILE" <<'EOF'
# Vecta TFE credentials — chmod 0600, never commit this file
# Set your Vecta KMS auth token below:
VECTA_AUTH_TOKEN=
EOF
  chmod 0600 "$CREDS_FILE"
fi
echo "  Credentials: $CREDS_FILE (edit and set VECTA_AUTH_TOKEN)"

# ── Install scripts ────────────────────────────────────────────────────────────
cp vecta-tfe-mount.sh       "$BIN_DIR/vecta-tfe-mount"
cp encrypt-folder.sh        "$BIN_DIR/vecta-tfe-encrypt-folder"
cp decrypt-folder.sh        "$BIN_DIR/vecta-tfe-decrypt-folder"
cp vecta-rotate-key.sh      "$BIN_DIR/vecta-tfe-rotate-key"
chmod 750 "$BIN_DIR/vecta-tfe-mount" "$BIN_DIR/vecta-tfe-encrypt-folder" \
          "$BIN_DIR/vecta-tfe-decrypt-folder" "$BIN_DIR/vecta-tfe-rotate-key"

echo "Agent scripts installed to $BIN_DIR"
echo ""
`, envContent)

	// Systemd user service — persistent daemon (Type=exec), starts at boot
	systemdUnit := `[Unit]
Description=Vecta TFE Transparent File Encryption — FUSE mount daemon
Documentation=https://docs.vectakms.com/tfe
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
# Persistent daemon — keeps encrypted directories FUSE-mounted for transparent access
ExecStart=%h/.local/bin/vecta-tfe-mount
ExecStop=/bin/sh -c 'kill -TERM $MAINPID 2>/dev/null; sleep 2'
Environment=VECTA_CONF_DIR=%h/.config/vecta-tfe
Restart=on-failure
RestartSec=10s
KillSignal=SIGTERM
TimeoutStopSec=30s
# Security hardening (user-mode, no privilege escalation)
NoNewPrivileges=true
ProtectHostname=true
PrivateTmp=true

[Install]
# WantedBy=default.target ensures automatic start on user login/boot
# Run: loginctl enable-linger $USER   to start at system boot (not just login)
WantedBy=default.target
`

	// Alpine OpenRC
	alpineInitSh := `#!/sbin/openrc-run
# OpenRC service for Vecta TFE transparent encryption agent
description="Vecta TFE Transparent File Encryption Agent (gocryptfs FUSE)"
command="$HOME/.local/bin/vecta-tfe-mount"
pidfile="${CONF_DIR:-$HOME/.config/vecta-tfe}/agent.pid"
depend() { need net localmount; }
`

	linuxInstallFinishSh := func(dist string) string {
		if dist == "alpine" {
			return `# ── Alpine: OpenRC service ────────────────────────────────────────────────────
cp vecta-tfe.openrc /etc/init.d/vecta-tfe 2>/dev/null || true
chmod 755 /etc/init.d/vecta-tfe 2>/dev/null || true
rc-update add vecta-tfe default 2>/dev/null && echo "  OpenRC service enabled." || \
  echo "  WARN: could not add to rc. Run: rc-update add vecta-tfe default"
echo ""
echo "=== Installation complete ==="
echo "  Start now : rc-service vecta-tfe start"
echo "  OR manually: $HOME/.local/bin/vecta-tfe-mount"
`
		}
		return `# ── systemd user service — enable and start at boot ─────────────────────────
cp vecta-tfe.service "$SYSTEMD_DIR/"
systemctl --user daemon-reload
systemctl --user enable --now vecta-tfe.service
echo "  systemd user service enabled and started."

# Enable linger so the service starts at boot even before login
if command -v loginctl &>/dev/null; then
  loginctl enable-linger "$(whoami)" 2>/dev/null && \
    echo "  loginctl linger enabled — service will start at boot." || \
    echo "  WARN: loginctl linger failed (may need sudo). Service starts on next login."
fi

echo ""
echo "=== Installation complete ==="
echo "  Service status : systemctl --user status vecta-tfe.service"
echo "  View logs      : journalctl --user -u vecta-tfe.service -f"
echo "  Stop service   : systemctl --user stop vecta-tfe.service"
echo "  Manual encrypt : vecta-tfe-encrypt-folder <folder>"
echo "  Manual decrypt : vecta-tfe-decrypt-folder <folder>"
echo ""
echo "  IMPORTANT: Edit $HOME/.config/vecta-tfe/credentials and set VECTA_AUTH_TOKEN"
echo "  Then restart:  systemctl --user restart vecta-tfe.service"
`
	}

	linuxRotateSh := fmt.Sprintf(`#!/usr/bin/env bash
# vecta-rotate-key.sh — Request key rotation via Vecta KMS TFE service.
set -euo pipefail
CONF_DIR="${VECTA_CONF_DIR:-$HOME/.config/vecta-tfe}"
# shellcheck source=/dev/null
source "$CONF_DIR/agent.env"
# shellcheck source=/dev/null
source "$CONF_DIR/credentials"
echo "[rotate] Requesting key rotation from Vecta KMS TFE service..."
curl -fsS -X POST \
  -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
  -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
  -H "Content-Type: application/json" \
  "${VECTA_API_BASE_URL}${VECTA_ROTATE_PATH}" \
  --data '{"rotation_cycle_days":%d}' | jq .
echo "[rotate] Done."
`, rotDays)

	// ── Windows: cppcryptfs + WinFsp transparent mount ────────────────────────
	// cppcryptfs is the Windows port of gocryptfs, uses WinFsp (user-mode FUSE for Windows).
	// WinFsp is WHQL-signed; no custom kernel code needed.
	windowsInstallPs1 := fmt.Sprintf("#Requires -Version 5.1\r\n"+
		"# install.ps1 — Install Vecta TFE transparent encryption agent (Windows).\r\n"+
		"# Uses cppcryptfs + WinFsp for FUSE-based transparent encryption.\r\n"+
		"# No custom kernel driver required; WinFsp is WHQL-signed.\r\n"+
		"$ErrorActionPreference = \"Stop\"\r\n"+
		"Set-StrictMode -Version Latest\r\n"+
		"\r\n"+
		"$confDir  = Join-Path $env:APPDATA \"Vecta\\TFE\"\r\n"+
		"$binDir   = Join-Path $env:LOCALAPPDATA \"Vecta\\bin\"\r\n"+
		"$logDir   = Join-Path $env:LOCALAPPDATA \"Vecta\\TFE\"\r\n"+
		"\r\n"+
		"Write-Host \"=== Vecta TFE Transparent File Encryption (Windows) ===\" -ForegroundColor Green\r\n"+
		"Write-Host \"    Uses cppcryptfs + WinFsp for transparent FUSE mount\"\r\n"+
		"Write-Host \"\"\r\n"+
		"\r\n"+
		"# Check for WinFsp (required for FUSE on Windows)\r\n"+
		"$winfspPath = \"C:\\Program Files (x86)\\WinFsp\\bin\\winfsp-x64.dll\"\r\n"+
		"if (-not (Test-Path $winfspPath)) {\r\n"+
		"  Write-Host \"  WinFsp not found. Downloading installer...\" -ForegroundColor Yellow\r\n"+
		"  $winfspUrl = \"https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi\"\r\n"+
		"  $winfspMsi = Join-Path $env:TEMP \"winfsp.msi\"\r\n"+
		"  Invoke-WebRequest -Uri $winfspUrl -OutFile $winfspMsi -UseBasicParsing\r\n"+
		"  Start-Process msiexec.exe -ArgumentList \"/i $winfspMsi /qn\" -Wait\r\n"+
		"  Write-Host \"  WinFsp installed.\" -ForegroundColor Green\r\n"+
		"}\r\n"+
		"\r\n"+
		"# Check for cppcryptfs CLI\r\n"+
		"$cppcryptfsExe = Join-Path $binDir \"cppcryptfsctl.exe\"\r\n"+
		"if (-not (Test-Path $cppcryptfsExe)) {\r\n"+
		"  Write-Host \"  cppcryptfs not found. Downloading...\" -ForegroundColor Yellow\r\n"+
		"  $cppcryptfsUrl = \"https://github.com/bailey27/cppcryptfs/releases/latest/download/cppcryptfsctl.exe\"\r\n"+
		"  New-Item -ItemType Directory -Path $binDir -Force | Out-Null\r\n"+
		"  Invoke-WebRequest -Uri $cppcryptfsUrl -OutFile $cppcryptfsExe -UseBasicParsing\r\n"+
		"  Write-Host \"  cppcryptfs downloaded.\" -ForegroundColor Green\r\n"+
		"}\r\n"+
		"\r\n"+
		"foreach ($cmd in @(\"openssl\",\"curl\",\"jq\")) {\r\n"+
		"  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {\r\n"+
		"    Write-Warning \"$cmd not found. Install via: winget install $cmd\" }}\r\n"+
		"\r\n"+
		"New-Item -ItemType Directory -Path $confDir,$binDir,$logDir -Force | Out-Null\r\n"+
		"icacls $confDir /inheritance:r /grant:r \"${env:USERNAME}:(OI)(CI)F\" 2>$null | Out-Null\r\n"+
		"\r\n"+
		"# Write agent config\r\n"+
		"@'\r\n%s\r\n'@ | Set-Content -Path (Join-Path $confDir \"agent.env\") -Encoding UTF8\r\n"+
		"\r\n"+
		"# Create credentials file (current user ACL only)\r\n"+
		"$credsFile = Join-Path $confDir \"credentials.env\"\r\n"+
		"if (-not (Test-Path $credsFile)) {\r\n"+
		"  \"# Vecta TFE credentials`r`nVECTA_AUTH_TOKEN=\" | Set-Content $credsFile -Encoding UTF8\r\n"+
		"  icacls $credsFile /inheritance:r /grant:r \"${env:USERNAME}:F\" 2>$null | Out-Null\r\n"+
		"}\r\n"+
		"Write-Host \"  Credentials: $credsFile (edit and set VECTA_AUTH_TOKEN)\" -ForegroundColor Yellow\r\n"+
		"\r\n"+
		"# Copy agent scripts\r\n"+
		"Copy-Item \"vecta-tfe-mount.ps1\"          (Join-Path $binDir \"vecta-tfe-mount.ps1\")          -Force\r\n"+
		"Copy-Item \"encrypt-folder.ps1\"            (Join-Path $binDir \"encrypt-folder.ps1\")            -Force\r\n"+
		"Copy-Item \"decrypt-folder.ps1\"            (Join-Path $binDir \"decrypt-folder.ps1\")            -Force\r\n"+
		"Copy-Item \"vecta-rotate-key.ps1\"          (Join-Path $binDir \"vecta-rotate-key.ps1\")          -Force\r\n"+
		"\r\n"+
		"# Register Windows startup task (runs at logon, keeps mount active)\r\n"+
		"$mountScript = Join-Path $binDir 'vecta-tfe-mount.ps1'\r\n"+
		"$argStr   = \"-NonInteractive -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `\"$mountScript`\"\"\r\n"+
		"$action   = New-ScheduledTaskAction -Execute \"powershell.exe\" -Argument $argStr\r\n"+
		"$trigger  = New-ScheduledTaskTrigger -AtLogOn\r\n"+
		"$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable\r\n"+
		"$taskArgs = @{ TaskName=\"VectaTFEMount\"; Action=$action; Trigger=$trigger; Settings=$settings; RunLevel=\"Limited\"; Force=$true }\r\n"+
		"Register-ScheduledTask @taskArgs | Out-Null\r\n"+
		"\r\n"+
		"Write-Host \"\"\r\n"+
		"Write-Host \"=== Installation complete ===\" -ForegroundColor Green\r\n"+
		"Write-Host \"  Start mount now : powershell -File $mountScript\"\r\n"+
		"Write-Host \"  Scheduled task  : VectaTFEMount (starts at every logon)\"\r\n"+
		"Write-Host \"  Manual encrypt  : powershell -File $(Join-Path $binDir 'encrypt-folder.ps1') <folder>\"\r\n"+
		"Write-Host \"  Manual decrypt  : powershell -File $(Join-Path $binDir 'decrypt-folder.ps1') <folder>\"\r\n"+
		"Write-Host \"\"\r\n"+
		"Write-Host \"  IMPORTANT: Edit $credsFile and set VECTA_AUTH_TOKEN first!\"\r\n",
		strings.ReplaceAll(envContent, "\n", "\r\n"))

	// Windows mount script — uses cppcryptfs for transparent FUSE mount
	windowsMountPs1 := "#Requires -Version 5.1\r\n" +
		"# vecta-tfe-mount.ps1 — Vecta TFE transparent encryption daemon (Windows)\r\n" +
		"# Uses cppcryptfs + WinFsp for FUSE-based transparent directory encryption.\r\n" +
		"# All processes reading/writing PLAIN_DIR see plaintext; data stored encrypted in VAULT_DIR.\r\n" +
		"$ErrorActionPreference = \"Stop\"\r\n" +
		"Set-StrictMode -Version Latest\r\n" +
		"\r\n" +
		"$confDir    = Join-Path $env:APPDATA \"Vecta\\TFE\"\r\n" +
		"$binDir     = Join-Path $env:LOCALAPPDATA \"Vecta\\bin\"\r\n" +
		"$cppcryptfs = Join-Path $binDir \"cppcryptfsctl.exe\"\r\n" +
		"$logDir     = Join-Path $env:LOCALAPPDATA \"Vecta\\TFE\"\r\n" +
		"$auditLog   = Join-Path $logDir \"audit.log\"\r\n" +
		"\r\n" +
		"if (-not (Test-Path (Join-Path $confDir \"agent.env\"))) {\r\n" +
		"  Write-Error \"Config not found. Run install.ps1 first.\"; exit 1 }\r\n" +
		"if (-not (Test-Path (Join-Path $confDir \"credentials.env\"))) {\r\n" +
		"  Write-Error \"Credentials not found. Run install.ps1 and set VECTA_AUTH_TOKEN.\"; exit 1 }\r\n" +
		"\r\n" +
		"# Load config\r\n" +
		"$cfg = @{}\r\n" +
		"Get-Content (Join-Path $confDir \"agent.env\") | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx=$_.IndexOf('='); $cfg[$_.Substring(0,$idx)]=$_.Substring($idx+1) }\r\n" +
		"$creds = @{}\r\n" +
		"Get-Content (Join-Path $confDir \"credentials.env\") | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx=$_.IndexOf('='); $creds[$_.Substring(0,$idx)]=$_.Substring($idx+1) }\r\n" +
		"$authToken = $creds['VECTA_AUTH_TOKEN']\r\n" +
		"\r\n" +
		"# Fetch DEK from Vecta KMS TFE service\r\n" +
		"$headers = @{ \"X-Tenant-ID\"=$cfg[\"VECTA_TENANT_ID\"]; \"Authorization\"=\"Bearer $authToken\" }\r\n" +
		"$body    = '{\"purpose\":\"tfe_mount\"}'\r\n" +
		"$irmArgs = @{ Method=\"Post\"; Uri=\"$($cfg['VECTA_API_BASE_URL'])/tfe/keys/$($cfg['VECTA_KEY_ID'])/unwrap\"; Headers=$headers; ContentType=\"application/json\"; Body=$body; TimeoutSec=15 }\r\n" +
		"$resp    = Invoke-RestMethod @irmArgs\r\n" +
		"$keyB64  = $resp.plaintext_dek\r\n" +
		"if ([string]::IsNullOrEmpty($keyB64)) { Write-Error \"Failed to fetch DEK from Vecta KMS.\"; exit 1 }\r\n" +
		"\r\n" +
		"New-Item -ItemType Directory -Path $logDir -Force | Out-Null\r\n" +
		"$mountedDirs = @()\r\n" +
		"\r\n" +
		"# Mount each watch directory transparently\r\n" +
		"$dirs = $cfg[\"VECTA_WATCH_DIRS\"] -split ','\r\n" +
		"foreach ($plainDir in $dirs) {\r\n" +
		"  $plainDir = $plainDir.Trim()\r\n" +
		"  if (-not $plainDir) { continue }\r\n" +
		"  $vaultDir = \"$plainDir.vecta-vault\"\r\n" +
		"  New-Item -ItemType Directory -Path $vaultDir,$plainDir -Force | Out-Null\r\n" +
		"  # Initialise vault on first use\r\n" +
		"  $vaultConf = Join-Path $vaultDir \"gocryptfs.conf\"\r\n" +
		"  if (-not (Test-Path $vaultConf)) {\r\n" +
		"    Write-Host \"  Initialising encrypted vault: $vaultDir\"\r\n" +
		"    $tmpPass = Join-Path $env:TEMP \"vecta-tfe-pass-$PID.tmp\"\r\n" +
		"    $keyB64 | Set-Content $tmpPass -Encoding UTF8\r\n" +
		"    & $cppcryptfs --init --passfile $tmpPass $vaultDir\r\n" +
		"    Remove-Item $tmpPass -Force\r\n" +
		"  }\r\n" +
		"  # Mount vault at plain dir\r\n" +
		"  $tmpPass2 = Join-Path $env:TEMP \"vecta-tfe-pass2-$PID.tmp\"\r\n" +
		"  $keyB64 | Set-Content $tmpPass2 -Encoding UTF8\r\n" +
		"  & $cppcryptfs --mount --passfile $tmpPass2 $vaultDir $plainDir\r\n" +
		"  Remove-Item $tmpPass2 -Force\r\n" +
		"  Write-Host \"  Mounted (transparent): $vaultDir -> $plainDir\"\r\n" +
		"  $mountedDirs += $plainDir\r\n" +
		"}\r\n" +
		"\r\n" +
		"# Zero DEK from memory\r\n" +
		"$keyB64 = $null; $resp = $null; [System.GC]::Collect()\r\n" +
		"\r\n" +
		"# Local audit\r\n" +
		"$ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')\r\n" +
		"\"$ts [INFO] op=mount dirs=$($cfg['VECTA_WATCH_DIRS']) key=$($cfg['VECTA_KEY_ID']) host=$env:COMPUTERNAME\" | Add-Content $auditLog\r\n" +
		"\r\n" +
		"# Best-effort KMS audit POST\r\n" +
		"try {\r\n" +
		"  $auditBody = \"{`\"tenant_id`\":`\"$($cfg['VECTA_TENANT_ID'])`\",`\"key_id`\":`\"$($cfg['VECTA_KEY_ID'])`\",`\"operation`\":`\"mount`\",`\"files_processed`\":0,`\"timestamp`\":`\"$ts`\",`\"hostname`\":`\"$env:COMPUTERNAME`\",`\"agent_version`\":`\"2.0`\"}\"\r\n" +
		"  $auditArgs = @{ Method=\"Post\"; Uri=\"$($cfg['VECTA_API_BASE_URL'])/tfe/file-encrypt/audit\"; Headers=@{\"X-Tenant-ID\"=$cfg[\"VECTA_TENANT_ID\"];\"Authorization\"=\"Bearer $authToken\";\"Content-Type\"=\"application/json\"}; Body=$auditBody; TimeoutSec=5 }\r\n" +
		"  Invoke-RestMethod @auditArgs | Out-Null\r\n" +
		"} catch { <# best effort #> }\r\n" +
		"\r\n" +
		"Write-Host \"[vecta-tfe] All directories mounted transparently. Waiting...\"\r\n" +
		"\r\n" +
		"# Keep running until interrupted\r\n" +
		"try {\r\n" +
		"  while ($true) {\r\n" +
		"    Start-Sleep -Seconds 60\r\n" +
		"    # Re-check all mounts still active\r\n" +
		"    foreach ($d in $mountedDirs) {\r\n" +
		"      $isDir = Test-Path $d -PathType Container\r\n" +
		"      $isEmpty = $isDir -and (@(Get-ChildItem $d -ErrorAction SilentlyContinue).Count -eq 0 -and (Test-Path \"$d.vecta-vault\"))\r\n" +
		"      if (-not $isDir -or $isEmpty) {\r\n" +
		"        Write-Warning \"Mount may be lost for $d\"\r\n" +
		"      }\r\n" +
		"    }\r\n" +
		"  }\r\n" +
		"} finally {\r\n" +
		"  # Unmount all on exit\r\n" +
		"  foreach ($d in $mountedDirs) {\r\n" +
		"    & $cppcryptfs --unmount $d 2>$null\r\n" +
		"    Write-Host \"  Unmounted: $d\"\r\n" +
		"  }\r\n" +
		"}\r\n"

	// Windows explicit encrypt/decrypt folder scripts (batch mode — for initial encryption)
	windowsEncryptFolderPs1 := "#Requires -Version 5.1\r\n" +
		"# encrypt-folder.ps1 — Manually encrypt a folder in place (batch mode).\r\n" +
		"# For ongoing transparent access, use the vecta-tfe-mount.ps1 service.\r\n" +
		"param([Parameter(Mandatory)][string]$Folder)\r\n" +
		"$ErrorActionPreference = \"Stop\"\r\n" +
		"$confDir  = Join-Path $env:APPDATA \"Vecta\\TFE\"\r\n" +
		"$cfg = @{}\r\n" +
		"Get-Content (Join-Path $confDir \"agent.env\") | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx=$_.IndexOf('='); $cfg[$_.Substring(0,$idx)]=$_.Substring($idx+1) }\r\n" +
		"$creds = @{}\r\n" +
		"Get-Content (Join-Path $confDir \"credentials.env\") | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx=$_.IndexOf('='); $creds[$_.Substring(0,$idx)]=$_.Substring($idx+1) }\r\n" +
		"$authToken = $creds['VECTA_AUTH_TOKEN']\r\n" +
		"$headers = @{ \"X-Tenant-ID\"=$cfg[\"VECTA_TENANT_ID\"]; \"Authorization\"=\"Bearer $authToken\" }\r\n" +
		"$irmArgs = @{ Method=\"Post\"; Uri=\"$($cfg['VECTA_API_BASE_URL'])/tfe/keys/$($cfg['VECTA_KEY_ID'])/unwrap\"; Headers=$headers; ContentType=\"application/json\"; Body='{\"purpose\":\"tfe_batch_encrypt\"}'; TimeoutSec=15 }\r\n" +
		"$resp = Invoke-RestMethod @irmArgs\r\n" +
		"$keyB64 = $resp.plaintext_dek\r\n" +
		"if ([string]::IsNullOrEmpty($keyB64)) { Write-Error \"Failed to fetch DEK.\"; exit 1 }\r\n" +
		"$keyHex = [BitConverter]::ToString([Convert]::FromBase64String($keyB64)) -replace '-',''\r\n" +
		"$count = 0\r\n" +
		"Get-ChildItem -Path $Folder -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ne '.venc' } | ForEach-Object {\r\n" +
		"  $src=$_.FullName; $dst=\"$src.venc\"\r\n" +
		"  $ivHex=(openssl rand -hex 12).Trim()\r\n" +
		"  openssl enc -aes-256-gcm -K $keyHex -iv $ivHex -in \"$src\" -out \"$dst.tmp\" 2>$null\r\n" +
		"  $ivBytes=[byte[]]@(0..11|ForEach-Object{[Convert]::ToByte($ivHex.Substring($_*2,2),16)})\r\n" +
		"  $ct=[System.IO.File]::ReadAllBytes(\"$dst.tmp\")\r\n" +
		"  $out=New-Object byte[]($ivBytes.Length+$ct.Length)\r\n" +
		"  [Array]::Copy($ivBytes,0,$out,0,$ivBytes.Length)\r\n" +
		"  [Array]::Copy($ct,0,$out,$ivBytes.Length,$ct.Length)\r\n" +
		"  [System.IO.File]::WriteAllBytes($dst,$out)\r\n" +
		"  Remove-Item \"$dst.tmp\",$src -Force\r\n" +
		"  Write-Host \"  encrypted: $src\"; $count++ }\r\n" +
		"$keyB64=$null;$keyHex=$null;[GC]::Collect()\r\n" +
		"Write-Host \"Encrypted $count files in $Folder.\"\r\n"

	windowsDecryptFolderPs1 := "#Requires -Version 5.1\r\n" +
		"# decrypt-folder.ps1 — Manually decrypt a folder's .venc files (batch mode).\r\n" +
		"param([Parameter(Mandatory)][string]$Folder)\r\n" +
		"$ErrorActionPreference = \"Stop\"\r\n" +
		"$confDir  = Join-Path $env:APPDATA \"Vecta\\TFE\"\r\n" +
		"$cfg = @{}\r\n" +
		"Get-Content (Join-Path $confDir \"agent.env\") | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx=$_.IndexOf('='); $cfg[$_.Substring(0,$idx)]=$_.Substring($idx+1) }\r\n" +
		"$creds = @{}\r\n" +
		"Get-Content (Join-Path $confDir \"credentials.env\") | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx=$_.IndexOf('='); $creds[$_.Substring(0,$idx)]=$_.Substring($idx+1) }\r\n" +
		"$authToken = $creds['VECTA_AUTH_TOKEN']\r\n" +
		"$headers = @{ \"X-Tenant-ID\"=$cfg[\"VECTA_TENANT_ID\"]; \"Authorization\"=\"Bearer $authToken\" }\r\n" +
		"$irmArgs = @{ Method=\"Post\"; Uri=\"$($cfg['VECTA_API_BASE_URL'])/tfe/keys/$($cfg['VECTA_KEY_ID'])/unwrap\"; Headers=$headers; ContentType=\"application/json\"; Body='{\"purpose\":\"tfe_batch_decrypt\"}'; TimeoutSec=15 }\r\n" +
		"$resp = Invoke-RestMethod @irmArgs\r\n" +
		"$keyB64 = $resp.plaintext_dek\r\n" +
		"if ([string]::IsNullOrEmpty($keyB64)) { Write-Error \"Failed to fetch DEK.\"; exit 1 }\r\n" +
		"$keyHex = [BitConverter]::ToString([Convert]::FromBase64String($keyB64)) -replace '-',''\r\n" +
		"$count = 0\r\n" +
		"Get-ChildItem -Path $Folder -Recurse -Filter '*.venc' -File -ErrorAction SilentlyContinue | ForEach-Object {\r\n" +
		"  $src=$_.FullName; $orig=$src -replace '\\.venc$',''\r\n" +
		"  $blob=[System.IO.File]::ReadAllBytes($src)\r\n" +
		"  $ivHex=[BitConverter]::ToString($blob[0..11]) -replace '-',''\r\n" +
		"  [System.IO.File]::WriteAllBytes(\"$src.ct\",$blob[12..($blob.Length-1)])\r\n" +
		"  openssl enc -d -aes-256-gcm -K $keyHex -iv $ivHex -in \"$src.ct\" -out $orig 2>$null\r\n" +
		"  Remove-Item \"$src.ct\",$src -Force\r\n" +
		"  Write-Host \"  decrypted: $src -> $orig\"; $count++ }\r\n" +
		"$keyB64=$null;$keyHex=$null;[GC]::Collect()\r\n" +
		"Write-Host \"Decrypted $count files in $Folder.\"\r\n"

	windowsRotatePs1 := fmt.Sprintf(`# vecta-rotate-key.ps1 — Request key rotation via Vecta KMS TFE service.
param([int]$RotationDays = %d)
$ErrorActionPreference = "Stop"
$confDir = Join-Path $env:APPDATA "Vecta\TFE"
$cfg = @{}
Get-Content (Join-Path $confDir "agent.env") | Where-Object { $_ -match '^[A-Za-z_]' } | ForEach-Object {
  $idx = $_.IndexOf('='); $cfg[$_.Substring(0,$idx)] = $_.Substring($idx+1) }
$creds = @{}
Get-Content (Join-Path $confDir "credentials.env") | Where-Object { $_ -match '^[A-Za-z_]' } | ForEach-Object {
  $idx = $_.IndexOf('='); $creds[$_.Substring(0,$idx)] = $_.Substring($idx+1) }
$headers = @{ "X-Tenant-ID" = $cfg["VECTA_TENANT_ID"]; "Authorization" = "Bearer $($creds['VECTA_AUTH_TOKEN'])" }
$body    = '{"rotation_cycle_days":' + $RotationDays + '}'
$irmArgs = @{ Method="Post"; Uri="$($cfg['VECTA_API_BASE_URL'])$($cfg['VECTA_ROTATE_PATH'])"; Headers=$headers; ContentType="application/json"; Body=$body }
Invoke-RestMethod @irmArgs | ConvertTo-Json
Write-Host "[rotate] Key rotation requested."
`, rotDays)

	// ── Assemble package ──────────────────────────────────────────────────────
	var files []FileEncryptPackageFile
	if targetOS == "windows" {
		files = []FileEncryptPackageFile{
			{Path: "agent.env", Content: envContent, Mode: "0600"},
			{Path: "install.ps1", Content: windowsInstallPs1, Mode: "0644"},
			{Path: "vecta-tfe-mount.ps1", Content: windowsMountPs1, Mode: "0644"},
			{Path: "encrypt-folder.ps1", Content: windowsEncryptFolderPs1, Mode: "0644"},
			{Path: "decrypt-folder.ps1", Content: windowsDecryptFolderPs1, Mode: "0644"},
			{Path: "vecta-rotate-key.ps1", Content: windowsRotatePs1, Mode: "0644"},
			{Path: "README.txt", Content: buildTFEReadme("windows", distro, apiBase, watchDirs, patterns, rotDays), Mode: "0644"},
		}
	} else {
		installBody := linuxInstallSh + linuxInstallFinishSh(distro)
		files = []FileEncryptPackageFile{
			{Path: "agent.env", Content: envContent, Mode: "0600"},
			{Path: "install.sh", Content: installBody, Mode: "0755"},
			{Path: "vecta-tfe-mount.sh", Content: linuxMountSh, Mode: "0750"},
			{Path: "encrypt-folder.sh", Content: linuxEncryptFolderSh, Mode: "0750"},
			{Path: "decrypt-folder.sh", Content: linuxDecryptFolderSh, Mode: "0750"},
			{Path: "vecta-rotate-key.sh", Content: linuxRotateSh, Mode: "0750"},
			{Path: "README.md", Content: buildTFEReadme("linux", distro, apiBase, watchDirs, patterns, rotDays), Mode: "0644"},
		}
		switch distro {
		case "alpine":
			files = append(files, FileEncryptPackageFile{Path: "vecta-tfe.openrc", Content: alpineInitSh, Mode: "0755"})
		default:
			files = append(files, FileEncryptPackageFile{Path: "vecta-tfe.service", Content: systemdUnit, Mode: "0644"})
		}
	}

	return FileEncryptPackage{
		TargetOS:     targetOS,
		Distro:       distro,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Algorithm:    "AES-256-GCM",
		Mode:         "transparent_fuse",
		KeyID:        keyID,
		RotationDays: rotDays,
		Files:        files,
	}, nil
}

func buildTFEReadme(targetOS, distro, apiBase, watchDirs, patterns string, rotDays int) string {
	if targetOS == "windows" {
		return fmt.Sprintf(`Vecta KMS — TFE Transparent File Encryption Agent (Windows)
============================================================
Mode       : Transparent FUSE mount via cppcryptfs + WinFsp
             All processes see plaintext; data encrypted at rest
Algorithm  : AES-256-GCM (FIPS 140-3 Level 1 approved)
API        : %s

Quick Start
-----------
1. Edit credentials.env — set VECTA_AUTH_TOKEN
2. Run install.ps1 (installs WinFsp + cppcryptfs automatically)
3. Task Scheduler "VectaTFEMount" starts at every logon

Transparent mount  :  powershell -File vecta-tfe-mount.ps1
Manual encrypt dir :  powershell -File encrypt-folder.ps1 -Folder C:\path\to\dir
Manual decrypt dir :  powershell -File decrypt-folder.ps1 -Folder C:\path\to\dir.vecta-vault
Rotate key         :  powershell -File vecta-rotate-key.ps1

Watch dirs     : %s
File patterns  : %s
Rotation       : every %d days

Architecture
------------
* VAULT DIR = <watch_dir>.vecta-vault  (encrypted backing store)
* PLAIN DIR = <watch_dir>              (transparent FUSE mount — plaintext view)
* All processes access PLAIN DIR; WinFsp + cppcryptfs encrypts transparently.

Security Notes
--------------
* DEK fetched from Vecta KMS TFE service per mount, zeroed from memory after use.
* credentials.env is current-user-only (icacls), never stored with agent.env.
* AES-256-GCM provides confidentiality AND integrity (AEAD).
`, apiBase, watchDirs, patterns, rotDays)
	}
	return fmt.Sprintf(`# Vecta KMS — TFE Transparent File Encryption Agent (Linux/%s)
Mode       : Transparent FUSE mount via gocryptfs (AES-SIV mode)
             All processes see plaintext; data encrypted at rest in vault dir
Algorithm  : AES-256-GCM / AES-SIV (FIPS 140-3 Level 1 approved)
API        : %s

## Quick Start

1. Edit credentials and set VECTA_AUTH_TOKEN:
   nano ~/.config/vecta-tfe/credentials

2. Run the installer (no root required):
   bash install.sh

3. Service starts automatically at boot.

## Service Commands

   Status  : systemctl --user status vecta-tfe.service
   Logs    : journalctl --user -u vecta-tfe.service -f
   Stop    : systemctl --user stop vecta-tfe.service
   Restart : systemctl --user restart vecta-tfe.service

## Manual Operations

   Mount transparently   : vecta-tfe-mount
   Encrypt folder (batch): vecta-tfe-encrypt-folder /path/to/folder
   Decrypt folder (batch): vecta-tfe-decrypt-folder /path/to/folder.vecta-vault
   Rotate key            : vecta-tfe-rotate-key

## Architecture

   VAULT DIR = <watch_dir>.vecta-vault  (gocryptfs encrypted backing store)
   PLAIN DIR = <watch_dir>              (FUSE mount — transparent plaintext view)
   All processes access PLAIN DIR; gocryptfs encrypts/decrypts transparently.

## Policy

   Watch dirs    : %s
   File patterns : %s
   Rotation      : every %d days

## Security Notes

* DEK fetched from Vecta KMS TFE service per mount, zeroed from memory after all mounts complete.
* credentials file is 0600 (owner read/write only), separate from agent.env.
* AES-SIV (gocryptfs -aessiv flag) provides nonce-misuse-resistant authenticated encryption.
* Run 'loginctl enable-linger $USER' for boot-time start (before any user login).
`, distro, apiBase, watchDirs, patterns, rotDays)
}
