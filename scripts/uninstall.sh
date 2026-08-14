#!/usr/bin/env bash
#
# poolgate — uninstall (one command). The mirror of scripts/install.sh.
#
# Usage:
#   ./scripts/uninstall.sh [--prefix DIR] [--service] [--purge] [--data-dir DIR] [--yes]
#
# Steps:  remove the installed binary from PREFIX/bin
#         --service      also remove the systemd unit (Linux) / launchd agent (macOS)
#         --purge        also DELETE the data dir (accounts, tokens, master key) — destructive
#         --data-dir DIR data dir to purge (else $POOLGATE_DATA_DIR, else ./poolgate-data)
#         --yes          do not prompt for the destructive --purge confirmation
#
# The binary is safe to remove (re-installable from source). --purge is
# irreversible: it deletes your encrypted accounts AND the master key that
# decrypts them, so it always confirms unless --yes is given.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PREFIX=""
DO_SERVICE=0
DO_PURGE=0
DATA_DIR=""
ASSUME_YES=0
BIN_NAME="poolgate"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage(){ sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)    PREFIX="${2:?--prefix needs a dir}"; shift 2 ;;
    --service)   DO_SERVICE=1; shift ;;
    --purge)     DO_PURGE=1; shift ;;
    --data-dir)  DATA_DIR="${2:?--data-dir needs a dir}"; shift 2 ;;
    -y|--yes)    ASSUME_YES=1; shift ;;
    -h|--help)   usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

# rm_path removes a file, using sudo only when the parent dir is not writable.
rm_path() {
  local p="$1"
  if [ -w "$(dirname "$p")" ]; then
    rm -f "$p"
  else
    log "removing $p (needs sudo)"
    sudo rm -f "$p"
  fi
}

# --- 1. remove the binary --------------------------------------------------
# Candidate locations: the explicit --prefix, the two install.sh defaults, and
# whatever is on PATH. De-duplicated; only existing files are removed.
declare -a candidates=()
if [ -n "$PREFIX" ]; then
  candidates+=("$PREFIX/bin/$BIN_NAME")
else
  candidates+=("/usr/local/bin/$BIN_NAME" "$HOME/.local/bin/$BIN_NAME")
  if on_path="$(command -v "$BIN_NAME" 2>/dev/null)"; then
    candidates+=("$on_path")
  fi
fi

removed=0
declare -a seen=()
for p in "${candidates[@]}"; do
  # skip duplicates
  dup=0
  for s in "${seen[@]:-}"; do [ "$s" = "$p" ] && dup=1 && break; done
  [ "$dup" -eq 1 ] && continue
  seen+=("$p")

  if [ -e "$p" ]; then
    rm_path "$p"
    log "removed binary: $p"
    removed=1
  fi
done
[ "$removed" -eq 1 ] || warn "no $BIN_NAME binary found in the checked locations."

# --- 2. optional: remove the service ---------------------------------------
if [ "$DO_SERVICE" -eq 1 ]; then
  case "$(uname -s)" in
    Linux)
      UNIT="/etc/systemd/system/poolgate.service"
      if [ -e "$UNIT" ]; then
        log "stopping + removing systemd unit $UNIT (needs sudo)"
        sudo systemctl disable --now poolgate 2>/dev/null || true
        sudo rm -f "$UNIT"
        sudo systemctl daemon-reload 2>/dev/null || true
        log "removed systemd unit."
      else
        warn "no systemd unit at $UNIT."
      fi
      ;;
    Darwin)
      PLIST="$HOME/Library/LaunchAgents/im.go2.poolgate.plist"
      if [ -e "$PLIST" ]; then
        log "unloading + removing launchd agent $PLIST"
        launchctl unload "$PLIST" 2>/dev/null || true
        rm -f "$PLIST"
        log "removed launchd agent."
      else
        warn "no launchd agent at $PLIST."
      fi
      ;;
    *) warn "unsupported OS for --service cleanup: $(uname -s)" ;;
  esac
else
  # Nudge the user if a service is present but they didn't ask to remove it.
  if [ -e "/etc/systemd/system/poolgate.service" ] || [ -e "$HOME/Library/LaunchAgents/im.go2.poolgate.plist" ]; then
    warn "a poolgate service is still installed — re-run with --service to remove it."
  fi
fi

# --- 3. optional: purge the data dir (DESTRUCTIVE) -------------------------
if [ "$DO_PURGE" -eq 1 ]; then
  # Resolve the data dir: explicit flag > env > install-time default (relative
  # to the current directory, matching config.DefaultDataDir).
  target="$DATA_DIR"
  [ -n "$target" ] || target="${POOLGATE_DATA_DIR:-}"
  [ -n "$target" ] || target="$REPO_ROOT/poolgate-data"

  if [ ! -d "$target" ]; then
    warn "no data dir found at '$target' — nothing to purge (pass --data-dir to point at yours)."
  else
    abs="$(cd "$target" && pwd)"
    log "data dir to purge: $abs"
    printf '     contents: '; ls -A "$abs" 2>/dev/null | tr '\n' ' '; printf '\n'
    warn "this permanently deletes your encrypted accounts AND the master key — it is IRREVERSIBLE."
    if [ "$ASSUME_YES" -ne 1 ]; then
      printf 'Type "yes" to delete %s: ' "$abs"
      read -r reply
      [ "$reply" = "yes" ] || die "aborted — data dir left intact."
    fi
    rm -rf "$abs"
    log "purged data dir: $abs"
  fi
else
  log "data dir left intact (pass --purge to delete accounts + master key)."
fi

log "Done."
