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

3. One-click link mode (HookCollector(..., link=LinkRegistry))
   The same collector additionally serves /go/<token>: the auditor sends that
   link to the Windows user, the browser shows a consent page and the download
   of a self-contained hooky-audit.cmd. Opening it asks permission natively,
   runs the read-only agent and POSTs the result back once - then the token
   is burned, the reports are generated automatically and the link is dead.

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
from . import link as _link

LinkRegistry = _link.LinkRegistry   # re-export for the interactive flows

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
    link = None            # link.LinkRegistry when a one-click link flow runs
    link_on_result = None  # callback(path) -> import rc, called on link result


_LINK_PATH = re.compile(r"^/go/([A-Za-z0-9_-]+)(?:/([a-z]+))?$")


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

    def _send_html(self, code, html):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, code, data, name):
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % name)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = (self.path.split("?", 1)[0].rstrip("/") or "/")
        if path in ("/health", "/"):
            self._send(200, {"status": "ok",
                             "tool": "Hooky hook collector",
                             "outdir": _HookState.outdir})
            return
        reg = _HookState.link
        m = _LINK_PATH.match(path)
        if reg is not None and m:
            self._handle_link(m.group(1), m.group(2), reg)
            return
        self._send(404, {"error": "use POST /hook"})

    def _handle_link(self, token, action, reg):
        """Serve the one-click consent flow: /go/<token>[/allow|/file|/deny]."""
        if token != reg.token:
            self.log_message("link request with unknown token from %s"
                             % self.client_address[0])
            self._send_html(410, _link.gone_page("this link does not exist"))
            return
        if not reg.live():
            self._send_html(410, _link.gone_page(reg.gone_reason()))
            return
        ip = self.client_address[0]
        if not action:
            if reg.state == "waiting":
                reg.state = "opened"
            reg.client_ip = ip
            reg.note("the user OPENED the audit link (from %s)" % ip)
            self._send_html(200, _link.consent_page(reg))
        elif action == "allow":
            if reg.state in ("waiting", "opened"):
                reg.state = "allowed"
            reg.client_ip = ip
            reg.note("the user ALLOWED the audit (from %s) - Windows asks "
                     "for permission once more when the file is opened" % ip)
            self._send_html(200, _link.allow_page(reg))
        elif action == "file":
            if reg.state == "waiting":
                reg.state = "opened"
            reg.client_ip = ip
            reg.note("the audit file was downloaded (from %s) - waiting "
                     "for it to run" % ip)
            try:
                host_hdr = self.headers.get("Host")
                uri = "http://%s/hook" % (host_hdr or "%s:%d" % (
                    controller_ip(), _HookState.port))
                data = _link.build_oneclick_cmd(uri, reg)
            except Exception as exc:
                self._send(500, {"error": "cannot build audit file: %s" % exc})
                return
            self._send_file(200, data.encode("utf-8"), _link.CMD_NAME)
        elif action == "deny":
            reg.state = "denied"
            reg.client_ip = ip
            reg.note("the user DECLINED the audit (from %s) - nothing was "
                     "collected" % ip)
            self._send_html(200, _link.deny_page())
        else:
            self._send(404, {"error": "unknown link action"})

    def do_POST(self):
        if self.path.rstrip("/") not in ("/hook", ""):
            self._send(404, {"error": "POST /hook only"})
            return
        supplied = (self.headers.get("X-Hooky-Token")
                    or self.headers.get("X-SecureAudit-Token")
                    or self.headers.get("X-VulnScope-Token") or "")
        reg = _HookState.link
        if reg is not None:
            # one-click link mode: the token must match the LIVE link
            if (not hmac.compare_digest(supplied, reg.token)) or not reg.live():
                self._send(403, {"error": "invalid or expired audit link token"})
                self.log_message("REJECTED request from %s (bad or used "
                                 "link token)" % self.client_address[0])
                return
        elif _HookState.token:
            # webhook mode: current header first, then legacy agent names
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
        if reg is not None:
            # one-click link mode: generate the reports NOW, then burn the
            # token so the link can never be used again (auto disconnect).
            reg.note("RESULT received from %s - generating the reports" % comp)
            ok = True
            cb = _HookState.link_on_result
            if cb is not None:
                try:
                    ok = cb(path) != 2
                except Exception:
                    ok = False
            if ok:
                reg.state = "used"
                reg.note("reports generated - the audit link is now closed")
                if _HookState.sink is not None:
                    try:
                        _HookState.sink._record(path)
                    except Exception:
                        pass
                self._send(200, {"status": "ok", "saved": fname,
                                 "link": "closed"})
            else:
                reg.note("report generation FAILED - the link stays open, "
                         "the file can be run again")
                self._send(500, {"error": "report generation failed - "
                                          "you may run the audit file again"})
            return
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

    Pass link=<LinkRegistry> (and optionally on_result=<callback>) to enable
    the one-click audit link: /go/<token> then serves the consent pages and
    an accepted result is handed to on_result before the token is burned.
    """

    def __init__(self, port, token, outdir, link=None, on_result=None):
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
        _HookState.link = link
        _HookState.link_on_result = on_result
        _HookState.port = port
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


def _print_link_banner(port, reg, outdir, ip=None):
    ip = ip or controller_ip()
    url = "http://%s:%d/go/%s" % (ip, port, reg.token)
    print()
    print("Hooky ONE-CLICK AUDIT LINK is ready")
    print("  Reports will be saved to : %s" % os.path.abspath(outdir))
    print("  Audit size               : %s" %
          ("quick (most important checks)" if reg.quick
           else "full - all Windows checks"))
    print("  Link valid for           : %d minutes, ONE audit only"
          % reg.ttl_minutes)
    print()
    print("  Send this link to the person whose PC you want to audit")
    print("  (chat, e-mail - any way you like):")
    print()
    print("      %s" % url)
    print()
    print("  Then everything runs by itself:")
    print("    1. they open the link and see a permission page")
    print("    2. they click 'I allow' - a small audit file downloads")
    print("    3. they open the file and click Yes on the Windows popup")
    print("    4. the read-only audit runs (~15-30 s), the result arrives here")
    print("    5. your reports are generated and the link closes by itself")
    print()
    print("  Works from any device that can reach this machine on your")
    print("  network (same Wi-Fi/LAN or VPN). Press Ctrl+C to stop waiting.")
    print()


def start_hook(port, token, outdir):
    """Run the collector until Ctrl+C. Returns process exit code (int)."""
    if not (1 <= port <= 65535):
        raise RemoteError("invalid hook port %d" % port)
    _HookState.token = token or ""
    _HookState.outdir = os.path.abspath(outdir)
    _HookState.port = port
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
