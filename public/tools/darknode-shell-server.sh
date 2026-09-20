#!/bin/bash
# ============================================================
# Darknode Shell Server (Bash edition)
# Quick WebSocket shell server using websocat.
#
# Install websocat:
#   cargo install websocat
#   # or on Debian/Ubuntu:
#   apt install websocat
#   # or download binary from:
#   https://github.com/vi/websocat/releases
#
# Usage:
#   ./darknode-shell-server.sh [PORT]
#
# Default port: 8765
# Only accepts localhost connections via websocat binding.
# ============================================================

set -euo pipefail

PORT="${1:-8765}"
TIMEOUT=30

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Check dependencies ──────────────────────────────────────
if ! command -v websocat &>/dev/null; then
    echo -e "${RED}ERROR: websocat not found.${NC}"
    echo "Install it:"
    echo "  cargo install websocat"
    echo "  apt install websocat"
    echo "  https://github.com/vi/websocat/releases"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo -e "${YELLOW}WARNING: jq not found. JSON parsing will be basic.${NC}"
    HAS_JQ=0
else
    HAS_JQ=1
fi

# ── Banner ──────────────────────────────────────────────────
echo -e "${CYAN}"
cat << 'BANNER'
  ____             _                      _
 |  _ \  __ _ _ __| | ___ __   ___   __| | ___
 | | | |/ _` | '__| |/ / '_ \ / _ \ / _` |/ _ \
 | |_| | (_| | |  |   <| | | | (_) | (_| |  __/
 |____/ \__,_|_|  |_|\_\_| |_|\___/ \__,_|\___|

 Shell Server v1.0 (bash edition)
BANNER
echo -e "${NC}"

echo -e "${YELLOW}================================================================${NC}"
echo -e "${YELLOW} WARNING: This server executes commands on YOUR machine.${NC}"
echo -e "${YELLOW} Only localhost connections are accepted.${NC}"
echo -e "${YELLOW}================================================================${NC}"
echo ""
echo -e "${GREEN}Listening on 127.0.0.1:${PORT}${NC}"
echo -e "Command timeout: ${TIMEOUT}s"
echo -e "Press Ctrl+C to stop."
echo ""

# ── Dangerous command patterns ──────────────────────────────
is_blocked() {
    local cmd="$1"
    case "$cmd" in
        *"rm -rf /"*|*"rm -rf /*"*)   return 0 ;;
        *"dd if="*)                    return 0 ;;
        *"mkfs"*)                      return 0 ;;
        *":(){ :|:& };:"*)            return 0 ;;
        *"> /dev/sd"*)                 return 0 ;;
        *"chmod 777 /"*)               return 0 ;;
        *"| sh"*|*"| bash"*)           return 0 ;;
    esac
    return 1
}

# ── Handler script ──────────────────────────────────────────
# websocat calls this for each message received.
# Input: one JSON line per message on stdin
# Output: JSON response lines on stdout
handle_message() {
    while IFS= read -r line; do
        # Parse JSON
        if [ "$HAS_JQ" -eq 1 ]; then
            msg_type=$(echo "$line" | jq -r '.type // ""' 2>/dev/null)
            cmd=$(echo "$line" | jq -r '.cmd // ""' 2>/dev/null)
        else
            # Basic parsing without jq
            msg_type=$(echo "$line" | grep -oP '"type"\s*:\s*"\K[^"]+' 2>/dev/null || echo "")
            cmd=$(echo "$line" | grep -oP '"cmd"\s*:\s*"\K[^"]+' 2>/dev/null || echo "")
        fi

        # Skip non-exec messages
        if [ "$msg_type" != "exec" ] || [ -z "$cmd" ]; then
            echo '{"type":"error","data":"Expected {\"type\":\"exec\",\"cmd\":\"...\"}"}'
            continue
        fi

        # Log command
        echo -e "${CYAN}[$(date +%H:%M:%S)] EXEC:${NC} $cmd" >&2

        # Safety check
        if is_blocked "$cmd"; then
            echo -e "${RED}[$(date +%H:%M:%S)] BLOCKED:${NC} $cmd" >&2
            echo "{\"type\":\"error\",\"data\":\"Command blocked by safety filter\"}"
            continue
        fi

        # Execute with timeout
        output=$(timeout "$TIMEOUT" bash -c "$cmd" 2>&1) || true
        exit_code=$?

        # Escape output for JSON
        if [ "$HAS_JQ" -eq 1 ]; then
            json_output=$(echo "$output" | jq -Rs '.')
            echo "{\"type\":\"output\",\"data\":$json_output}"
        else
            # Basic JSON escaping without jq
            escaped=$(echo "$output" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | tr '\n' '\a' | sed 's/\a/\\n/g')
            echo "{\"type\":\"output\",\"data\":\"$escaped\"}"
        fi

        # Send exit code if non-zero
        if [ "$exit_code" -ne 0 ]; then
            echo "{\"type\":\"exit_code\",\"data\":\"$exit_code\"}"
        fi
    done
}

# ── Start server ────────────────────────────────────────────
# websocat listens on the port and pipes each WebSocket
# connection through our handler function.
export -f handle_message is_blocked
export HAS_JQ TIMEOUT CYAN RED NC

websocat -s "127.0.0.1:${PORT}" --text -e sh-c:'handle_message'
