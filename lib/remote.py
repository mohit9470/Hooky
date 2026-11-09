#!/usr/bin/env python3
"""Hooky - remote Windows connectivity layer.

Two independent transports, both driven from the Linux controller:

1. SSH push mode (--windows user@host[:port])
   Uses the system ssh/scp clients to copy the bundled Windows agent onto the
   target, execute it through Windows OpenSSH and pull the JSON result back.
   No Python dependencies, no software installation on the Windows side.

2. HTTP hook mode (--hook --hook-port N --hook-token T)
   Runs a small stdlib-only HTTP collector. Windows agents POST their JSON to
   http://<controller>:<port>/hook with an X-Hooky-Token header
   (the agent supports this natively via -Uri/-Token). Results are saved as
   files ready for `hooky.py get` / --windows-import.

Everything here is read-only with respect to both hosts (apart from copying
the agent script and its JSON output into the Windows user's profile).
"""

import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import sanitize

# Path of the bundled PowerShell agent (hooky/windows/hooky-agent.ps1)
AGENT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "windows", "hooky-agent.ps1")

REMOTE_AGENT_NAME = "hooky-agent.ps1"
REMOTE_RESULT_NAME = "hooky-result.json"


class RemoteError(Exception):
    """Raised when a remote Windows audit cannot be completed."""


# --------------------------------------------------------------------------- #
#  Target parsing
# --------------------------------------------------------------------------- #

def parse_windows_target(spec):
    """Parse 'user@host', 'user@host:port', 'user@[2001:db8::1]:2222'.

    Returns dict(user, host, port). Raises RemoteError on garbage.
    """
    spec = (spec or "").strip()
    if not spec:
        raise RemoteError("empty Windows target specification")
    user = None
    if "@" in spec:
        user, _, spec = spec.rpartition("@")
    if not user:
        raise RemoteError(
            "Windows target must be user@host (got %r) - the SSH user is "
            "required" % spec)
    port = 22
    host = spec
    if spec.startswith("["):                      # user@[v6]:port
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", spec)
        if not m:
            raise RemoteError("cannot parse IPv6 target %r" % spec)
        host = m.group(1)
        if m.group(2):
            port = int(m.group(2))
    elif spec.count(":") == 1:                    # user@host:port (IPv4)
        host, p = spec.rsplit(":", 1)
        if p.isdigit():
            port = int(p)
    if not host:
        raise RemoteError("Windows target has an empty hostname")
    return {"user": user, "host": host, "port": port}


def target_label(t):
    return "%s@%s" % (t["user"], t["host"])


# --------------------------------------------------------------------------- #
#  SSH transport
# --------------------------------------------------------------------------- #

def _ssh_base(t, timeout=15):
    return ["ssh", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=%d" % timeout,
            "-p", str(t["port"]),
            "%s@%s" % (t["user"], t["host"])]


def _run(cmd, timeout, what):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RemoteError("ssh/scp client not found on this machine "
                          "(openssh-client package required)")
    except subprocess.TimeoutExpired:
        raise RemoteError("%s timed out after %ss" % (what, timeout))
    if p.returncode != 0:
        raise RemoteError("%s failed (rc=%d): %s"
                          % (what, p.returncode,
                             sanitize((p.stderr or p.stdout or "").strip(), 500,
                                      single_line=True)))
    return p


def preflight_ssh(t):
    """Verify ssh connectivity + command execution on the Windows host."""
    p = _run(_ssh_base(t) + ["echo hooky-ssh-ok"], 30, "SSH connection test")
    if "hooky-ssh-ok" not in (p.stdout or ""):
        raise RemoteError(
            "SSH works but the target did not answer the echo test "
            "(is the default shell functional?). Output: %s"
            % sanitize(p.stdout, 200, single_line=True))


def run_ssh_audit(target_spec, result_dir, quick=False):
    """Full push-and-collect audit of one Windows host over SSH.

    Returns the parsed agent result dict. Raises RemoteError on any failure.
    """
    if not os.path.isfile(AGENT_PATH):
        raise RemoteError("bundled Windows agent missing: %s" % AGENT_PATH)
    t = parse_windows_target(target_spec)
    label = target_label(t)

    preflight_ssh(t)
    base = _ssh_base(t)

    # 1. upload the agent
    _run(["scp", "-P", str(t["port"]),
          "-o", "StrictHostKeyChecking=accept-new",
          os.path.abspath(AGENT_PATH),
          "%s:%s" % (target_label(t), REMOTE_AGENT_NAME)],
         120, "agent upload to %s" % label)

    # 2. execute it (default OpenSSH shell may be cmd.exe or powershell.exe -
    #    both accept this invocation)
    timeout = 300 if quick else 900
    p = _run(base + ["powershell -NoProfile -ExecutionPolicy Bypass "
                     "-File %s -OutFile %s" % (REMOTE_AGENT_NAME,
                                               REMOTE_RESULT_NAME)],
             timeout, "agent execution on %s" % label)
    tail = [ln for ln in (p.stdout or "").splitlines() if ln.strip()][-4:]

    # 3. fetch the JSON result
    os.makedirs(result_dir, exist_ok=True)
    local = os.path.join(
        result_dir, "agent_%s_%s.json"
        % (re.sub(r"[^A-Za-z0-9_.-]", "_", t["host"]),
           datetime.now().strftime("%Y%m%d_%H%M%S")))
    _run(["scp", "-P", str(t["port"]),
          "-o", "StrictHostKeyChecking=accept-new",
          "%s:%s" % (target_label(t), REMOTE_RESULT_NAME), local],
         120, "result download from %s" % label)

    # 4. best-effort cleanup on the target
    try:
        subprocess.run(base + ["cmd /c del /q %s %s"
                               % (REMOTE_AGENT_NAME, REMOTE_RESULT_NAME)],
                       capture_output=True, text=True, timeout=30)
    except Exception:
        pass

    with open(local, "r", encoding="utf-8-sig") as fh:
        result = json.load(fh)
    result["_source"] = {"target": target_spec, "local_file": local,
                         "agent_log": tail}
    return result


# --------------------------------------------------------------------------- #
#  HTTP hook collector
# --------------------------------------------------------------------------- #

class _HookState(object):
    """Shared config for the HTTP handler."""
    token = ""
    outdir = ""
    sink = None


def controller_ip():
    """Best-effort IP of this machine's primary interface (for printouts)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def _result_computer(data):
    comp = data.get("computer")
    if not comp:
        sysd = ((data.get("collectors") or {}).get("system") or {}).get("data") or {}
        comp = sysd.get("computer_name")
    return str(comp) or "windows-host"


class _HookHandler(BaseHTTPRequestHandler):
    server_version = "HookyHook/2.0"
    protocol_version = "HTTP/1.1"

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # /health
        if self.path.rstrip("/") in ("/health", ""):
            self._send(200, {"status": "ok",
                             "tool": "Hooky hook collector",
                             "outdir": _HookState.outdir})
        else:
            self._send(404, {"error": "use POST /hook"})

    def do_POST(self):
        if self.path.rstrip("/") not in ("/hook", ""):
            self._send(404, {"error": "POST /hook only"})
            return
        if _HookState.token:
            # current header first, then the legacy names of older agents
            supplied = (self.headers.get("X-Hooky-Token")
                        or self.headers.get("X-SecureAudit-Token")
                        or self.headers.get("X-VulnScope-Token") or "")
            if not hmac.compare_digest(supplied, _HookState.token):
                self._send(403, {"error": "invalid or missing "
                                          "X-Hooky-Token"})
                self.log_message("REJECTED request from %s (bad token)"
                                 % self.client_address[0])
                return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 64 * 1024 * 1024:
                raise ValueError("bad Content-Length")
            data = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except Exception as exc:
            self._send(400, {"error": "invalid JSON body: %s" % exc})
            return
        os.makedirs(_HookState.outdir, exist_ok=True)
        comp = re.sub(r"[^A-Za-z0-9_.-]", "_", _result_computer(data))
        fname = "hook_%s_%s.json" % (comp,
                                     datetime.now().strftime("%Y%m%d_%H%M%S"))
        path = os.path.join(_HookState.outdir, fname)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        if _HookState.sink is not None:
            try:
                _HookState.sink._record(path)
            except Exception:
                pass
        self._send(200, {"status": "ok", "saved": fname})
        self.log_message("ACCEPTED result from %s -> %s"
                         % (_result_computer(data), fname))

    def log_message(self, fmt, *args):  # console friendly
        print("  [hook] %s %s" % (self.address_string(), fmt % args))


class HookCollector(object):
    """Non-blocking hook collector for interactive flows.

    .start() runs the HTTP server in a daemon thread; every accepted POST
    is saved under .outdir and its path is pushed onto .queue, so the main
    thread can wait for results and keep prompting the user.
    """

    def __init__(self, port, token, outdir):
        if not (1 <= port <= 65535):
            raise RemoteError("invalid hook port %d" % port)
        self.port = port
        self.token = token or ""
        self.outdir = os.path.abspath(outdir)
        self.queue = []          # list of saved file paths (newest last)
        self._srv = None
        self._thread = None
        _HookState.token = self.token
        _HookState.outdir = self.outdir
        _HookState.sink = self
        os.makedirs(self.outdir, exist_ok=True)

    def _record(self, path):
        self.queue.append(path)

    @property
    def ip(self):
        return controller_ip()

    @property
    def uri(self):
        return "http://%s:%d/hook" % (self.ip, self.port)

    def start(self):
        self._srv = ThreadingHTTPServer(("0.0.0.0", self.port), _HookHandler)
        self._srv.daemon_threads = True
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None

    def wait_for_result(self, timeout=2.0):
        """Wait up to `timeout` seconds for one result file. Returns path/None."""
        end = time.time() + timeout
        while time.time() < end:
            if self.queue:
                return self.queue.pop(0)
            time.sleep(0.1)
        return None


def _print_hook_banner(port, token, outdir, ip=None):
    ip = ip or controller_ip()
    uri = "http://%s:%d/hook" % (ip, port)
    print()
    print("Hooky webhook collector listening on 0.0.0.0:%d" % port)
    print("  results dir : %s" % os.path.abspath(outdir))
    print("  token       : %s" % ("required (X-Hooky-Token header)"
                                   if token else "NOT set - open endpoint!"))
    print()
    print("Run this ONE command on each Windows host (PowerShell as Administrator):")
    print("  powershell -NoProfile -ExecutionPolicy Bypass -File hooky-agent.ps1 ^")
    print("      -Uri %s -Token '%s'" % (uri, token or "<token>"))
    print()
    print("(The agent file hooky-agent.ps1 is in this tool's windows/ folder -")
    print(" copy it to the Windows host first, or export with:  python3 hooky.py agent)")
    print()


def start_hook(port, token, outdir):
    """Run the collector until Ctrl+C. Returns process exit code (int)."""
    if not (1 <= port <= 65535):
        raise RemoteError("invalid hook port %d" % port)
    _HookState.token = token or ""
    _HookState.outdir = os.path.abspath(outdir)
    os.makedirs(_HookState.outdir, exist_ok=True)
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", port), _HookHandler)
    except OSError as exc:
        raise RemoteError("cannot bind hook port %d: %s" % (port, exc))
    srv.daemon_threads = True
    _print_hook_banner(port, token, outdir)
    print("Each result lands in the results dir; audit it with:")
    print("  python3 hooky.py get <results.json>")
    print("Press Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nHook collector stopped.")
    finally:
        srv.server_close()
    return 0
