#!/usr/bin/env python3
"""Darknode Shell Server -- local agent for browser terminal access.
Run this on your machine, then connect from the Darknode Web Shell.

Requirements:
    pip install websockets

Usage:
    python3 darknode-shell-server.py [--port PORT] [--allow-remote] [--no-filter] [--timeout SECS]

Security:
    By default only localhost connections are accepted.
    All executed commands are logged to stderr.
    Dangerous command patterns are blocked unless --no-filter is used.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time

try:
    import websockets
except ImportError:
    print("ERROR: 'websockets' library required. Install it:")
    print("  pip install websockets")
    sys.exit(1)

# ── Logging ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("darknode-shell")

# ── Dangerous command patterns ───────────────────────────────────────────

BLOCKED_PATTERNS = [
    r"rm\s+(-\w*)?r\w*\s+/\s*$",           # rm -rf /
    r"rm\s+(-\w*)?r\w*\s+/\*",             # rm -rf /*
    r"dd\s+if=",                             # dd raw disk writes
    r"mkfs",                                 # format filesystems
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", # fork bomb
    r">\s*/dev/sd[a-z]",                     # write to raw device
    r"chmod\s+(-\w+\s+)?777\s+/",           # chmod 777 /
    r"wget\s+.*\|\s*sh",                    # piped download execution
    r"curl\s+.*\|\s*sh",                    # piped download execution
    r"mv\s+/\s",                             # mv / somewhere
]

BLOCKED_RE = [re.compile(p, re.IGNORECASE) for p in BLOCKED_PATTERNS]


def is_blocked(cmd, filtering_enabled):
    """Return True if the command matches a dangerous pattern."""
    if not filtering_enabled:
        return False
    for pattern in BLOCKED_RE:
        if pattern.search(cmd):
            return True
    return False


# ── Command execution ────────────────────────────────────────────────────

async def execute_command(cmd, timeout_secs):
    """Execute a shell command and return (stdout+stderr, exit_code)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.expanduser("~"),
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_secs
            )
            output = stdout.decode("utf-8", errors="replace") if stdout else ""
            return output, proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "(command timed out after {}s)".format(timeout_secs), -1
    except Exception as e:
        return "Execution error: {}".format(str(e)), -1


# ── WebSocket handler ────────────────────────────────────────────────────

def make_handler(timeout_secs, filtering_enabled, allow_remote):
    """Create a WebSocket handler with the given configuration."""

    async def handler(websocket):
        remote = websocket.remote_address
        remote_ip = remote[0] if remote else "unknown"
        log.info("Connection from %s", remote_ip)

        # Localhost check
        if not allow_remote and remote_ip not in ("127.0.0.1", "::1", "localhost"):
            log.warning("Rejected non-localhost connection from %s", remote_ip)
            await websocket.send(json.dumps({
                "type": "error",
                "data": "Connection rejected: only localhost allowed. "
                        "Start server with --allow-remote to accept remote connections."
            }))
            await websocket.close()
            return

        await websocket.send(json.dumps({
            "type": "info",
            "data": "Darknode Shell Server ready. Executing on: {}".format(
                os.uname().nodename
            ),
        }))

        try:
            async for raw in websocket:
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    await websocket.send(json.dumps({
                        "type": "error",
                        "data": "Invalid JSON message",
                    }))
                    continue

                msg_type = msg.get("type", "")
                cmd = msg.get("cmd", "").strip()

                if msg_type == "signal":
                    sig = msg.get("signal", "SIGINT")
                    log.info("Signal: %s (ignored -- no active process handle)", sig)
                    continue

                if msg_type != "exec" or not cmd:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "data": 'Expected {"type":"exec","cmd":"..."}',
                    }))
                    continue

                log.info("EXEC [%s]: %s", remote_ip, cmd)

                # Safety check
                if is_blocked(cmd, filtering_enabled):
                    log.warning("BLOCKED dangerous command: %s", cmd)
                    await websocket.send(json.dumps({
                        "type": "error",
                        "data": "Command blocked by safety filter: {}".format(cmd),
                    }))
                    continue

                # Execute
                output, exit_code = await execute_command(cmd, timeout_secs)

                # Send output
                await websocket.send(json.dumps({
                    "type": "output",
                    "data": output,
                }))

                # Send exit code if non-zero
                if exit_code != 0:
                    await websocket.send(json.dumps({
                        "type": "exit_code",
                        "data": str(exit_code),
                    }))

        except websockets.exceptions.ConnectionClosed:
            log.info("Connection closed: %s", remote_ip)
        except Exception as e:
            log.error("Handler error: %s", e)

    return handler


# ── Banner ───────────────────────────────────────────────────────────────

BANNER = r"""
  ____             _                      _
 |  _ \  __ _ _ __| | ___ __   ___   __| | ___
 | | | |/ _` | '__| |/ / '_ \ / _ \ / _` |/ _ \
 | |_| | (_| | |  |   <| | | | (_) | (_| |  __/
 |____/ \__,_|_|  |_|\_\_| |_|\___/ \__,_|\___|

 Shell Server v1.0
"""

DISCLAIMER = """
 ================================================================
  WARNING: This server executes shell commands on YOUR machine.
  Anyone who can reach this port can run arbitrary commands.
  By default, only localhost connections are accepted.
 ================================================================
"""


# ── Main ─────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Darknode Shell Server -- local WebSocket agent for browser terminal."
    )
    parser.add_argument(
        "--port", type=int, default=8765,
        help="Port to listen on (default: 8765)"
    )
    parser.add_argument(
        "--allow-remote", action="store_true",
        help="Accept connections from non-localhost IPs (DANGEROUS)"
    )
    parser.add_argument(
        "--no-filter", action="store_true",
        help="Disable dangerous command filtering (DANGEROUS)"
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Command execution timeout in seconds (default: 30)"
    )
    return parser.parse_args()


async def main():
    args = parse_args()

    print(BANNER)
    print(DISCLAIMER)

    if args.allow_remote:
        print(" !! REMOTE ACCESS ENABLED -- any IP can connect and execute commands !!")
        print("")

    if args.no_filter:
        print(" !! COMMAND FILTERING DISABLED -- dangerous commands will NOT be blocked !!")
        print("")

    filtering_enabled = not args.no_filter
    handler = make_handler(args.timeout, filtering_enabled, args.allow_remote)

    bind_addr = "0.0.0.0" if args.allow_remote else "127.0.0.1"

    async with websockets.serve(handler, bind_addr, args.port):
        log.info("Listening on %s:%d", bind_addr, args.port)
        log.info("Command timeout: %ds", args.timeout)
        log.info("Command filtering: %s", "ON" if filtering_enabled else "OFF")
        log.info("Remote access: %s", "ALLOWED" if args.allow_remote else "localhost only")
        log.info("")
        log.info("Connect from Darknode Web Shell or any WebSocket client.")
        log.info("Press Ctrl+C to stop.")
        log.info("")

        # Run forever until interrupted
        stop = asyncio.get_event_loop().create_future()

        def _stop(*_):
            if not stop.done():
                stop.set_result(None)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                asyncio.get_event_loop().add_signal_handler(sig, _stop)
            except NotImplementedError:
                signal.signal(sig, _stop)

        await stop

    log.info("Server stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown.")
