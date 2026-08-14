#!/usr/bin/env bash
#
# poolgate — build & install from source (one command).
#
# Usage:
#   ./scripts/install.sh [--prefix DIR] [--init] [--service] [--no-build]
#
# Steps:  verify Go >= 1.25  ->  build the binary  ->  install to PREFIX/bin
#         --init      then run `poolgate init` (provision config + first-passkey link)
#         --service   install a systemd unit (Linux) / launchd agent (macOS) for `poolgate serve`
#         --no-build  skip the build (install an already-built ./bin/poolgate)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PREFIX=""
DO_INIT=0
DO_SERVICE=0
DO_BUILD=1
BIN_NAME="poolgate"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage(){ sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)   PREFIX="${2:?--prefix needs a dir}"; shift 2 ;;
    --init)     DO_INIT=1; shift ;;
    --service)  DO_SERVICE=1; shift ;;
    --no-build) DO_BUILD=0; shift ;;
    -h|--help)  usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

# --- prerequisites ---
command -v go >/dev/null 2>&1 || die "Go toolchain not found — install Go >= 1.25 (https://go.dev/dl/)."
log "Go: $(go env GOVERSION 2>/dev/null || echo unknown)"

# --- install prefix (prefer a no-sudo location) ---
if [ -z "$PREFIX" ]; then
  if [ -w /usr/local/bin ]; then PREFIX="/usr/local"; else PREFIX="$HOME/.local"; fi
fi
BIN_DIR="$PREFIX/bin"
mkdir -p "$BIN_DIR"

# --- build ---
if [ "$DO_BUILD" -eq 1 ]; then
  log "Building $BIN_NAME from source (CGO-free, static)..."
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$REPO_ROOT/bin/$BIN_NAME" ./cmd/poolgate
fi
[ -x "$REPO_ROOT/bin/$BIN_NAME" ] || die "binary not found at ./bin/$BIN_NAME (drop --no-build to build it)."

# --- install ---
log "Installing -> $BIN_DIR/$BIN_NAME"
install -m 0755 "$REPO_ROOT/bin/$BIN_NAME" "$BIN_DIR/$BIN_NAME"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) log "NOTE: $BIN_DIR is not on your PATH — add it (e.g. export PATH=\"$BIN_DIR:\$PATH\")." ;;
esac

# --- optional: init ---
if [ "$DO_INIT" -eq 1 ]; then
  log "Provisioning (poolgate init)..."
  "$BIN_DIR/$BIN_NAME" init
fi

# --- optional: service ---
if [ "$DO_SERVICE" -eq 1 ]; then
  case "$(uname -s)" in
    Linux)
      UNIT="/etc/systemd/system/poolgate.service"
      log "Writing systemd unit $UNIT (needs sudo)"
      sudo tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=poolgate — Codex/ChatGPT account-pool proxy
After=network-online.target

[Service]
ExecStart=$BIN_DIR/$BIN_NAME serve
Restart=on-failure
User=$USER
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
      sudo systemctl daemon-reload
      log "Enable + start with:  sudo systemctl enable --now poolgate"
      ;;
    Darwin)
      PLIST="$HOME/Library/LaunchAgents/im.go2.poolgate.plist"
      log "Writing launchd agent $PLIST"
      mkdir -p "$(dirname "$PLIST")"
      cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>im.go2.poolgate</string>
  <key>ProgramArguments</key><array><string>$BIN_DIR/$BIN_NAME</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
      log "Load with:  launchctl load $PLIST"
      ;;
    *) die "unsupported OS for --service: $(uname -s)" ;;
  esac
fi

log "Done."
[ "$DO_INIT" -eq 1 ] || log "Next: '$BIN_NAME init' to provision + get your first-passkey link."
log "Then: '$BIN_NAME import <path>' to add an account, and '$BIN_NAME serve' to run."
