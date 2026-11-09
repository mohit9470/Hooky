#!/usr/bin/env python3
"""
Hooky - Simple Cross-Platform Security Audit & Reporting Toolkit
======================================================================

Read-only security auditor with a zero-memorisation interactive menu:

    python3 hooky.py            <- just run it; it asks what you want to do

Simple commands (all optional - the menu does the same):

    python3 hooky.py scan       # audit THIS Linux system
    python3 hooky.py win        # audit a Windows system (wizard: SSH or webhook)
    python3 hooky.py win admin@win-host          # straight SSH push audit
    python3 hooky.py hook       # webhook: Windows agents send results to you
    python3 hooky.py get FILE   # audit a received Windows result file
    python3 hooky.py agent      # export the Windows agent script
    python3 hooky.py checks     # show the full test catalogue

Linux is audited locally with shell commands (60 tests). Windows hosts are
audited through the bundled read-only PowerShell agent: pushed over SSH,
received through the webhook collector, or imported from a file. All
findings land in one timestamped report bundle (HTML dashboard, PDF, JSON,
CSV) naming each vulnerability, its exact location, the evidence and the
step-by-step fix.

Classic long options (--all, --windows, --windows-import, ...) still work
for scripts, cron jobs and CI pipelines.
"""

import argparse
import glob as _glob
import os
import shutil
import sys
import time
import traceback
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.core import (TOOL_NAME, TOOL_VERSION, SEVERITY_ORDER, AuditContext,
                      collect_metadata)
from lib import checks_hardening, checks_auth, checks_network, \
    checks_packages, checks_secrets, checks_enterprise, checks_windows
from lib import report_data, report_html, report_pdf
from lib import remote
from lib.remote import RemoteError

MODULES = {
    "hardening": ("System Hardening", checks_hardening),
    "auth": ("Users & Authentication", checks_auth),
    "network": ("Network Exposure", checks_network),
    "packages": ("Packages & Known CVEs", checks_packages),
    "secrets": ("Secrets & Credentials", checks_secrets),
    "enterprise": ("Enterprise & Compliance", checks_enterprise),
}

DEFAULT_OUTDIR = "hooky_reports"
DEFAULT_HOOKDIR = "hooky_results"
WIN_TITLE = "Windows Security Audit"
LINUX_TITLE = "Full System Security Audit"

# ANSI colours
C = {"red": "\033[91m", "grn": "\033[92m", "yel": "\033[93m", "blu": "\033[94m",
     "cyn": "\033[96m", "dim": "\033[2m", "b": "\033[1m", "r": "\033[0m"}
USE_COLOR = sys.stdout.isatty()


def say(color, msg):
    if USE_COLOR and color in C:
        print("%s%s%s" % (C[color], msg, C["r"]))
    else:
        print(msg)


SEV_ANSI = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yel", "LOW": "blu"}


def n_linux_tests():
    return sum(len(mod.CHECKS) for _label, mod in MODULES.values())


def n_win_tests():
    return len(checks_windows.CHECKS)


def now_hms():
    return datetime.now().strftime("%H:%M:%S")


# --------------------------------------------------------------------------- #
#  Tiny interactive helpers
# --------------------------------------------------------------------------- #

def ask(prompt, default=None):
    """Read one line; on EOF/Interrupt return the default (or empty string)."""
    try:
        val = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default if default is not None else ""
    return val or (default if default is not None else "")


def confirm(prompt, default_yes=True):
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        ans = input("%s %s " % (prompt, suffix)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default_yes
    if not ans:
        return default_yes
    return ans in ("y", "yes")


def ask_outdir():
    return ask("  Report output directory [%s]: " % DEFAULT_OUTDIR,
               default=DEFAULT_OUTDIR)


# --------------------------------------------------------------------------- #
#  Help text: every command, 2-3 lines of usage each
# --------------------------------------------------------------------------- #

HELP_TEXT = """\
{t}{name} {ver}{r} - simple cross-platform security audit & reporting toolkit

USAGE
  python3 hooky.py                    interactive menu - nothing to memorise
  python3 hooky.py COMMAND [ARGS]     simple commands (described below)
  python3 hooky.py [LONG OPTIONS]     classic flags for scripts, cron, CI

COMMANDS
{c}  scan{r}    Audit THIS Linux system (60 checks: hardening, auth, network,
          packages/CVEs, secrets, enterprise compliance).
          usage: python3 hooky.py scan [-o DIR] [-f FORMATS] [--quick]
          Asks where to save the reports, runs every module and writes one
          timestamped bundle: HTML dashboard + PDF + JSON + CSV.
          Run with sudo for full coverage; without root some checks skip.

{c}  win{r}     Audit a Windows system - over SSH or through the webhook.
          usage: python3 hooky.py win [user@host]
          With user@host it pushes the read-only PowerShell agent over SSH,
          runs it and pulls the JSON result back. Without an argument a
          short wizard lets you choose SSH or the webhook link instead.

{c}  hook{r}    Receive Windows results over HTTP - no SSH access needed.
          usage: python3 hooky.py hook [--hook-port N] [--hook-token TOK]
          Starts a webhook collector and prints a ready-made PowerShell
          command; run it on each Windows host and its results arrive here
          as JSON and can be audited with one confirmation.

{c}  get{r}     Audit a saved Windows result file (webhook or manual copy).
          usage: python3 hooky.py get FILE [FILE...] [-o DIR] [-f FORMATS]
          Accepts single files, directories and wildcards; runs all 29
          Windows checks and writes the timestamped report bundle.

{c}  agent{r}   Export the read-only Windows agent script.
          usage: python3 hooky.py agent [FILE]
          Copies the bundled PowerShell collector to FILE (default:
          ./hooky-agent.ps1) so it can be transferred to Windows hosts
          manually before using 'win' or 'hook'.

{c}  checks{r}  Show the full test catalogue.
          usage: python3 hooky.py checks
          Lists every check ID and name: 60 Linux checks (HS/AU/NW/PK/SC/EC)
          and 29 Windows checks (WIN).

{c}  menu{r}    Force the interactive menu (same as running with no arguments).
          usage: python3 hooky.py menu
          Zero memorising: pick 1-5, answer the prompts, get the report.

{c}  help{r}    Show this help. Works as: python3 hooky.py help / -h / -help / --help

OPTIONS (classic long flags - all optional, kept for scripts and cron)
  -a, --all              run all six Linux modules (default)
  -m, --modules LIST     comma-separated subset: hardening,auth,network,
                         packages,secrets,enterprise
  -o, --output-dir DIR   report directory (default: ./hooky_reports)
  -f, --formats LIST     report formats (default: html,pdf,json,csv)
  -t, --title TEXT       title shown on the reports
  --quick                shorter filesystem-scan timeouts (faster)
  --list-checks          print the check catalogue and exit
  --windows USER@HOST    audit a Windows host over SSH (repeatable)
  --windows-import FILE  audit a received agent result JSON (repeatable)
  --no-local             skip the local Linux audit (Windows targets only)
  --export-agent FILE    copy the Windows agent to FILE and exit
  --hook                 run the webhook collector (Ctrl+C to stop)
  --hook-port N          webhook TCP port (default: 8090)
  --hook-token TOKEN     token agents must send (default: hooky-hook-token,
                         or env HOOKY_HOOK_TOKEN)
  --hook-dir DIR         webhook results directory (default: ./hooky_results)
  -V, --version          print the version and exit
  -h, -help, --help      show this help and exit

EXIT CODES   0 = clean   1 = vulnerabilities found   2 = tool error
MORE         run 'python3 hooky.py' in a terminal for the interactive menu;
             see README.md for the full walkthrough and report examples.
"""


class _HookyParser(argparse.ArgumentParser):
    """argparse parser whose -h / -help / --help prints the custom HELP_TEXT
    (every command with 2-3 lines of usage) instead of the raw flag dump."""

    def print_help(self, file=None):
        try:                       # colours only on a real terminal
            tty = sys.stdout.isatty()
        except Exception:
            tty = False
        if tty:
            txt = HELP_TEXT.format(t=C["b"], c=C["cyn"], r=C["r"],
                                   name=TOOL_NAME, ver=TOOL_VERSION)
        else:
            txt = HELP_TEXT.format(t="", c="", r="",
                                   name=TOOL_NAME, ver=TOOL_VERSION)
        print(txt, file=file)


def build_arg_parser():
    p = _HookyParser(
        prog="hooky.py", add_help=False,
        description="%s %s - simple cross-platform security audit & reporting "
                    "toolkit (run without arguments for the interactive menu)"
                    % (TOOL_NAME, TOOL_VERSION),
        epilog="exit codes: 0 = clean, 1 = vulnerabilities found, 2 = tool error")
    p.add_argument("-h", "-help", "--help", action="help", default=argparse.SUPPRESS,
                   help="show the full command help (every command + usage) and exit")
    p.add_argument("-a", "--all", action="store_true",
                   help="run all six Linux audit modules (default)")
    p.add_argument("-m", "--modules",
                   help="comma-separated modules: %s" % ",".join(MODULES))
    p.add_argument("-o", "--output-dir", default="./" + DEFAULT_OUTDIR,
                   help="directory for generated reports (default: ./%s)"
                        % DEFAULT_OUTDIR)
    p.add_argument("-f", "--formats", default="html,pdf,json,csv",
                   help="report formats to write (default: html,pdf,json,csv)")
    p.add_argument("-t", "--title", default=LINUX_TITLE,
                   help="title shown on the reports")
    p.add_argument("--quick", action="store_true",
                   help="faster scan with shorter filesystem-scan timeouts")
    p.add_argument("--list-checks", action="store_true",
                   help="print the full check catalogue and exit")
    p.add_argument("-V", "--version", action="version",
                   version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    g = p.add_argument_group("Windows remote auditing")
    g.add_argument("--windows", action="append", default=[],
                   metavar="user@host[:port]",
                   help="audit a Windows host over SSH: the bundled agent is "
                        "pushed, executed and its JSON result pulled back "
                        "(repeatable; needs key-based SSH to the host)")
    g.add_argument("--windows-import", dest="windows_import", action="append",
                   default=[], metavar="FILE",
                   help="audit a Windows agent result JSON that was collected "
                        "manually or received through the webhook "
                        "(repeatable)")
    g.add_argument("--no-local", action="store_true",
                   help="skip the local Linux audit (audit only Windows targets)")
    g.add_argument("--export-agent", metavar="FILE",
                   help="copy the bundled PowerShell agent to FILE for manual "
                        "transfer to a Windows host, then exit")
    g.add_argument("--hook", action="store_true",
                   help="run the webhook collector that Windows agents POST "
                        "their results to (Ctrl+C to stop)")
    g.add_argument("--hook-port", type=int, default=8090,
                   help="TCP port for the webhook (default: 8090)")
    g.add_argument("--hook-token", dest="hook_token",
                   default=os.environ.get("HOOKY_HOOK_TOKEN")
                   or os.environ.get("SECUREAUDIT_HOOK_TOKEN")
                   or os.environ.get("VULNSCOPE_HOOK_TOKEN")
                   or "hooky-hook-token",
                   help="required token agents must send (default: "
                        "hooky-hook-token / $HOOKY_HOOK_TOKEN)")
    g.add_argument("--hook-dir", default="./" + DEFAULT_HOOKDIR,
                   help="directory where webhook results are saved "
                        "(default: ./%s)" % DEFAULT_HOOKDIR)
    return p


def catalogue():
    for label, mod in MODULES.values():
        say("cyn", "\n[%s]" % label)
        for fn in mod.CHECKS:
            print("  %-8s %s" % (fn.check_id, fn.check_name))
    say("cyn", "\n[Windows Systems]  (audited via: win / hook / get)")
    for fn in checks_windows.CHECKS:
        print("  %-8s %s" % (fn.check_id, fn.check_name))


# --------------------------------------------------------------------------- #
#  Windows result pipeline (shared by SSH / webhook / imported files)
# --------------------------------------------------------------------------- #

def run_windows_targets(args, md):
    """Audit every requested Windows target (SSH + imported results)."""
    findings, tests, targets = [], [], []
    for spec in args.windows:
        try:
            say("cyn", "\n[+] Windows target %s: connecting over SSH..." % spec)
            result = remote.run_ssh_audit(spec, os.path.dirname(
                os.path.abspath(args.output_dir)) or ".", quick=args.quick)
        except RemoteError as exc:
            say("red", "  [!]  Windows target %s failed: %s" % (spec, exc))
            say("red", "     (fix SSH access, or use menu option 3 / 'get' with "
                       "an agent result collected via the webhook)")
            return None
        findings, tests, info = _audit_agent_result(
            result, "SSH %s" % spec, findings, tests)
        targets.append(info)
    for path in args.windows_import:
        try:
            wctx = checks_windows.load_result_file(path)
            result = wctx.result
        except ValueError as exc:
            say("red", "  [!]  %s" % exc)
            return None
        findings, tests, info = _audit_agent_result(
            result, path, findings, tests)
        targets.append(info)
    return findings, tests, targets


def _audit_agent_result(result, source, findings, tests):
    """Run all WIN-xxx checks on one parsed agent result."""
    wctx = checks_windows.WinContext(result)
    hmd = checks_windows.host_metadata(wctx)
    say("cyn", "\n[+] Windows target: %s (%s)  source: %s"
        % (hmd["hostname"], hmd["os"], source))
    print("    agent      : %s | elevated: %s | collectors: %d/%d ok"
        % (wctx.result.get("agent_version"),
           "yes" if wctx.result.get("elevated") else "no",
           sum(1 for c in wctx.collectors.values() if c.get("ok")),
           len(wctx.collectors)))
    wf, wt = checks_windows.run_all(wctx)
    findings.extend(wf)
    tests.extend(wt)
    vulns = [f for f in wf if f.status == "VULNERABLE"]
    info = {"source": source, "computer": hmd["hostname"], "os": hmd["os"],
            "build": hmd["kernel"], "elevated": bool(hmd["privileged"]),
            "collected_at": hmd["audit_time"], "tests": len(wt),
            "vulnerable_tests": len(set(f.check_id for f in vulns)),
            "findings": len(vulns)}
    worst = max(vulns, key=lambda f: f.score) if vulns else None
    if worst:
        say(SEV_ANSI.get(worst.severity, "yel"),
            "    result     : %d vulnerable finding(s), worst: %s %s (%.1f)"
            % (len(vulns), worst.severity, worst.check_id, worst.score))
    else:
        say("grn", "    result     : no vulnerable findings")
    return findings, tests, info


# --------------------------------------------------------------------------- #
#  The audit + report pipeline
# --------------------------------------------------------------------------- #

def run_audit(args):
    modules = {}
    if args.modules:
        for name in args.modules.split(","):
            name = name.strip().lower()
            if name not in MODULES:
                say("red", "Unknown module '%s'. Available: %s"
                    % (name, ", ".join(MODULES)))
                return 2
            modules[name] = MODULES[name]
    else:
        modules = dict(MODULES)

    has_targets = bool(args.windows or args.windows_import)
    if args.no_local and not has_targets:
        say("red", "--no-local requested but no Windows target was given "
                   "(use --windows or --windows-import).")
        return 2
    if args.no_local:
        modules = {}

    ctx = AuditContext(quick=args.quick)
    md = collect_metadata(ctx)

    print()
    if args.no_local:
        say("cyn", "%s %s - Windows Remote Audit" % (TOOL_NAME, TOOL_VERSION))
    else:
        say("cyn", "%s %s - Linux Security Audit%s"
            % (TOOL_NAME, TOOL_VERSION,
               " (+ Windows targets)" if has_targets else ""))
    say("dim", "-" * 72)
    print("  Started at    : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("  Target        : %s (%s)" % (md["fqdn"], md["os"]))
    if args.no_local:
        print("  Role          : Linux controller (local Linux audit skipped)")
    if has_targets:
        print("  Windows targets: %s" % ", ".join(
            args.windows + ["import:%s" % p for p in args.windows_import]))
    print("  Platform      : %s | kernel %s (%s)" % (md["hardware_model"],
                                                      md["kernel"], md["arch"]))
    print("  Privilege     : %s" % ("root (full audit)" if ctx.is_root else
                                   "unprivileged user '%s' (reduced coverage)" % ctx.user))
    print("  Modules       : %s" % (", ".join(m[0] for m in modules.values())
                                    or "(none - Windows targets only)"))
    print("  Output        : %s" % os.path.abspath(args.output_dir))
    say("dim", "-" * 72)

    findings, tests = [], []
    t_start = time.time()
    for _key, (label, mod) in modules.items():
        say("cyn", "\n[+] Module: %s  (%d checks)" % (label, len(mod.CHECKS)))
        for fn in mod.CHECKS:
            t0 = time.time()
            try:
                res = fn(ctx)
                if not isinstance(res, list) or not res:
                    raise RuntimeError("check returned empty/invalid result")
            except Exception:
                res = [__import__("lib.core", fromlist=["core"]).skipped_finding(
                    fn, "system-wide", "Test crashed: %s"
                    % traceback.format_exc(limit=1).strip())]
            dur_ms = int((time.time() - t0) * 1000)
            findings.extend(res)
            vulns = [f for f in res if f.status == "VULNERABLE"]
            if vulns:
                worst = max(vulns, key=lambda f: f.score)
                say(SEV_ANSI.get(worst.severity, "yel"),
                    "  [VULN]  %-8s %s  ->  %d finding(s), worst: %s (%.1f)"
                    % (fn.check_id, fn.check_name[:46], len(vulns),
                       worst.severity, worst.score))
            elif any(f.status == "SECURE" for f in res):
                say("grn", "  [PASS]  %-8s %s" % (fn.check_id, fn.check_name[:58]))
            elif any(f.status == "INFO" for f in res):
                say("dim", "  [INFO]  %-8s %s" % (fn.check_id, fn.check_name[:58]))
            else:
                why = res[0].evidence or res[0].description or ""
                say("dim", "  [SKIP]  %-8s %s  (%s)"
                    % (fn.check_id, fn.check_name[:42], why[:60]))
            locs = "; ".join(dict.fromkeys(f.location for f in res))[:300]
            tests.append({"check_id": fn.check_id, "name": fn.check_name,
                          "category": fn.check_category,
                          "status": ("VULNERABLE" if vulns else
                                     "SECURE" if any(f.status == "SECURE" for f in res)
                                     else "INFO" if any(f.status == "INFO" for f in res)
                                     else "SKIPPED"),
                          "duration_ms": dur_ms, "locations": locs,
                          "findings": len(vulns), "host": "local"})

    # ---------------- Windows targets ----------------
    targets_info = []
    if has_targets:
        wres = run_windows_targets(args, md)
        if wres is None:
            return 2
        wf, wt, targets_info = wres
        findings.extend(wf)
        tests.extend(wt)
        md["remote_targets"] = targets_info
    md["no_local"] = bool(args.no_local)

    duration = time.time() - t_start
    summary = report_data.build_summary(findings, tests, duration)

    # ---------------- console summary ----------------
    print()
    say("dim", "-" * 72)
    say("b", "AUDIT SUMMARY")
    print("  Finished at    : %s  (took %.1f s)"
          % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), duration))
    print("  Tests conducted : %d   (vulnerable: %d | passed: %d | skipped: %d)"
          % (summary["total_tests"], summary["tests_vulnerable"],
             summary["tests_secure"], summary["tests_skipped"]))
    print("  Findings        : %d critical, %d high, %d medium, %d low"
          % (summary["by_severity"]["CRITICAL"], summary["by_severity"]["HIGH"],
             summary["by_severity"]["MEDIUM"], summary["by_severity"]["LOW"]))
    print("  Risk rating     : %s" % summary["risk_rating"])
    if targets_info:
        print("  Windows results : %s" % "; ".join(
            "%s: %d vulnerable finding(s)" % (t["computer"], t["findings"])
            for t in targets_info))
    if summary["tests_vulnerable"]:
        vulns = sorted((f for f in findings if f.status == "VULNERABLE"),
                       key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.score))
        say("yel", "\n  Top findings (worst per test):")
        seen_ids = set()
        shown = 0
        for f in vulns:
            if f.check_id in seen_ids:
                continue
            seen_ids.add(f.check_id)
            say(SEV_ANSI.get(f.severity, "yel"),
                "   %-9s %-8s %s" % (f.severity, f.check_id, f.name[:58]))
            shown += 1
            if shown >= 10:
                break

    # ---------------- write reports ----------------
    outdir = os.path.abspath(args.output_dir)
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    host_for_name = md["hostname"] or "host"
    if args.no_local and targets_info:
        host_for_name = targets_info[0]["computer"] or host_for_name
    safe_host = "".join(ch if ch.isalnum() or ch in "-_." else "_"
                        for ch in host_for_name)
    base = "Hooky_Report_%s_%s" % (safe_host, stamp)
    formats = [x.strip().lower() for x in args.formats.split(",") if x.strip()]
    written = []

    if "json" in formats:
        p = report_data.write_json(md, summary, findings, tests,
                                   os.path.join(outdir, base + ".json"), args.title)
        written.append(p)
    if "csv" in formats:
        p = report_data.write_csv(findings, os.path.join(outdir, base + ".csv"))
        written.append(p)
    if "html" in formats:
        p = report_html.generate_html(md, summary, findings, tests,
                                      os.path.join(outdir, base + ".html"),
                                      args.title)
        written.append(p)
    if "pdf" in formats:
        try:
            p = report_pdf.generate_pdf(md, summary, findings, tests,
                                        os.path.join(outdir, base + ".pdf"),
                                        args.title)
            written.append(p)
        except ImportError as exc:
            say("red", "  [!]  PDF skipped: %s" % exc)
        except Exception:
            say("red", "  [!]  PDF generation failed:\n%s"
                % traceback.format_exc(limit=2))

    say("grn", "\n  Reports written (timestamped):")
    for p in written:
        print("    %s" % p)
    if written:
        say("cyn", "\n  Next: open the .html file in your browser - it is the "
                   "interactive dashboard.")

    rc = 1 if summary["tests_vulnerable"] else 0
    say("dim", "\n  Exit code: %d (%s)" % (rc, "vulnerabilities found" if rc
                                           else "clean"))
    return rc


def import_files(paths, outdir=None, title=WIN_TITLE, quick=False,
                 formats=None):
    """Audit one or more Windows agent result files (webhook/import flow)."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(_glob.glob(os.path.join(p, "*.json"))))
        elif any(ch in p for ch in "*?"):
            files.extend(sorted(_glob.glob(p)))
        else:
            files.append(p)
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        say("red", "Result file(s) not found: %s" % ", ".join(missing))
        return 2
    if not files:
        say("red", "No result files given.")
        return 2
    ns = build_arg_parser().parse_args([])
    ns.no_local = True
    ns.windows_import = files
    ns.output_dir = outdir or ("./" + DEFAULT_OUTDIR)
    ns.title = title
    ns.quick = bool(quick)
    if formats:
        ns.formats = formats
    return run_audit(ns)


# --------------------------------------------------------------------------- #
#  Interactive flows
# --------------------------------------------------------------------------- #

def linux_flow():
    outdir = ask_outdir()
    try:
        if os.geteuid() != 0:
            say("dim", "  Tip: run 'sudo python3 hooky.py scan' for full "
                       "coverage - without root some tests are skipped.")
    except AttributeError:
        pass
    if not confirm("  Start the Linux audit now?", default_yes=True):
        return 0
    args = build_arg_parser().parse_args(
        ["--all", "--output-dir", outdir, "--title", LINUX_TITLE])
    return run_audit(args)


def ssh_flow():
    spec = ask("  Windows target as user@host (e.g. administrator@winsrv01): ")
    if not spec or "@" not in spec:
        say("red", "  A target in the form user@host is required "
                   "(example: administrator@winsrv01).")
        return 2
    outdir = ask_outdir()
    say("")
    say("b", "  Permission check - this will, using your SSH account on %s:" % spec)
    print("    1. copy the read-only Hooky agent (one PowerShell script)")
    print("    2. run it there - it changes NOTHING on the system (~1 minute)")
    print("    3. fetch the JSON result, then delete both files from the host")
    if not confirm("  Continue?", default_yes=True):
        say("dim", "  Cancelled - nothing was sent.")
        return 0
    args = build_arg_parser().parse_args(
        ["--windows", spec, "--no-local", "--output-dir", outdir,
         "--title", WIN_TITLE])
    return run_audit(args)


def webhook_flow():
    say("cyn", "  The Windows host will SEND its audit result to this machine "
               "over HTTP - no SSH needed.")
    port_s = ask("  Webhook port [8090]: ", default="8090")
    try:
        port = int(port_s)
    except ValueError:
        port = 8090
    token = ask("  Security token [press Enter to auto-generate]: ")
    if not token:
        import secrets as _secrets
        token = "hooky-" + _secrets.token_hex(8)
        say("dim", "  generated token: %s" % token)
    outdir = ask("  Save received results to [%s]: " % DEFAULT_HOOKDIR,
                 default=DEFAULT_HOOKDIR)
    try:
        coll = remote.HookCollector(port, token, outdir)
    except RemoteError as exc:
        say("red", "  [!]  %s" % exc)
        return 2
    try:
        coll.start()
    except OSError as exc:
        say("red", "  [!]  Cannot start webhook on port %d: %s" % (port, exc))
        return 2
    remote._print_hook_banner(port, token, outdir, ip=coll.ip)
    say("b", "  Waiting for Windows results ... (Ctrl+C to stop)")
    received, audited, last_rc = [], set(), 0
    try:
        while True:
            path = coll.wait_for_result(timeout=1.0)
            if path:
                received.append(path)
                say("grn", "\n  [%s] RESULT RECEIVED: %s" % (now_hms(), path))
                if confirm("  Audit it now and generate the report?"):
                    last_rc = import_files([path])
                    audited.add(path)
                    say("dim", "  Continuing to wait for more results... "
                               "(Ctrl+C to stop)")
    except KeyboardInterrupt:
        print()
    finally:
        coll.stop()
    pending = [p for p in received if p not in audited]
    if pending:
        say("b", "\n  %d result(s) were received but not yet audited." % len(pending))
        if confirm("  Audit them and generate the report(s) before exit?"):
            last_rc = import_files(pending)
    elif not received:
        print("  No results were received - copy the printed command to the "
              "Windows host and try again.")
    print("  Webhook collector stopped.")
    return last_rc


def get_flow():
    raw = ask("  Result file, directory or wildcard "
              "(e.g. %s/hook_WS01.json): " % DEFAULT_HOOKDIR)
    if not raw:
        say("red", "  No file given.")
        return 2
    return import_files([raw])


def _windows_submenu():
    while True:
        print("""
  How do you want to connect to the Windows system?
    1) Connect now over SSH      (I have SSH access to the Windows host)
    2) Generate a webhook link   (Windows sends the result to me - no SSH)
    b) Back""")
        c = ask("  Choose [1-2, b]: ", default="b")
        if c in ("b", "B", ""):
            return 0
        if c == "1":
            return ssh_flow()
        if c == "2":
            return webhook_flow()
        say("red", "  Please answer 1, 2 or b.")


MENU = """  1) Audit this Linux system
  2) Audit a Windows system
  3) Receive results from Windows (webhook link - no SSH needed)
  4) Audit a saved Windows result file
  5) Show all security checks
  0) Exit"""


def run_menu():
    while True:
        print()
        say("cyn", "=" * 72)
        say("b", "  %s %s - Simple Cross-Platform Security Audit" % (TOOL_NAME, TOOL_VERSION))
        say("cyn", "=" * 72)
        print("  Local Linux: %d tests   |   Windows: %d tests   |   "
              "Reports: HTML + PDF + JSON + CSV" % (n_linux_tests(), n_win_tests()))
        say("dim", "-" * 72)
        print(MENU)
        c = ask("  Choose an option [0-5]: ", default="0")
        if c in ("0", "q", "Q"):
            print("  Bye - stay secure!")
            return 0
        if c == "1":
            rc = linux_flow()
            if rc in (0, 1):
                return rc
        elif c == "2":
            rc = _windows_submenu()
            if rc in (0, 1):
                return rc
        elif c == "3":
            rc = webhook_flow()
            return rc if rc in (0, 1) else 2
        elif c == "4":
            rc = get_flow()
            if rc in (0, 1):
                return rc
        elif c == "5":
            catalogue()
            ask("\n  Press Enter to return to the menu...", default="")
        else:
            say("red", "  Please choose a number from 0 to 5.")


# --------------------------------------------------------------------------- #
#  Entry point: simple commands first, then classic flags
# --------------------------------------------------------------------------- #

SIMPLE = {"scan", "linux", "win", "windows", "hook", "get", "import",
          "agent", "checks", "list", "menu", "help"}


def _export_agent(path):
    if not os.path.isfile(remote.AGENT_PATH):
        say("red", "Bundled Windows agent missing: %s" % remote.AGENT_PATH)
        return 2
    shutil.copyfile(remote.AGENT_PATH, path)
    say("grn", "Windows agent written to %s" % os.path.abspath(path))
    print("Transfer it to the Windows host and run (PowerShell as Administrator):")
    print("  powershell -NoProfile -ExecutionPolicy Bypass -File hooky-agent.ps1")
    print("Then audit the result here:")
    print("  python3 hooky.py get hooky-agent-output.json")
    return 0


def _get_parser():
    """Mini parser for 'hooky.py get FILE... [flags]' (flags with values are
    handled properly instead of being mistaken for file names)."""
    p = argparse.ArgumentParser(prog="hooky.py get", add_help=False)
    p.add_argument("-o", "--output-dir", dest="output_dir", default=None)
    p.add_argument("-f", "--formats", dest="formats", default=None)
    p.add_argument("-t", "--title", dest="title", default=None)
    p.add_argument("--quick", action="store_true", default=False)
    p.add_argument("files", nargs="*")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # ---------- simple, memorable commands ----------
    if argv and argv[0] in SIMPLE:
        cmd, rest = argv[0], argv[1:]
        if cmd in ("scan", "linux"):
            argv = ["--all"] + rest
        elif cmd in ("win", "windows"):
            if rest and not rest[0].startswith("-"):
                argv = ["--no-local", "--windows", rest[0]] + rest[1:]
            elif sys.stdin.isatty():
                return _windows_submenu()
            else:
                build_arg_parser().print_usage()
                say("red", "'win' needs a target:  python3 hooky.py win "
                           "administrator@win-host\n(or run the interactive "
                           "menu:  python3 hooky.py menu)")
                return 2
        elif cmd == "hook":
            argv = ["--hook"] + rest
        elif cmd in ("get", "import"):
            g = _get_parser().parse_args(rest)
            return import_files(
                g.files,
                outdir=g.output_dir,
                title=g.title or WIN_TITLE,
                quick=g.quick,
                formats=g.formats)
        elif cmd == "agent":
            path = next((a for a in rest if not a.startswith("-")),
                        "./hooky-agent.ps1")
            return _export_agent(path)
        elif cmd in ("checks", "list"):
            catalogue()
            return 0
        elif cmd == "menu":
            return run_menu()          # forced menu, even with piped input
        elif cmd == "help":
            build_arg_parser().print_help()
            return 0
    else:
        # unknown bare word -> explain instead of argparse noise
        if argv and not argv[0].startswith("-"):
            say("red", "Unknown command %r. Simple commands: scan | win | "
                       "hook | get | agent | checks | menu\n"
                       "For every command with usage examples:  "
                       "python3 hooky.py help  (or -help)" % argv[0])
            return 2

    # ---------- bare run: interactive menu (TTY) or help ----------
    if not argv:
        if sys.stdin.isatty():
            return run_menu()
        build_arg_parser().print_help()
        return 0

    # ---------- classic flag pipeline ----------
    args = build_arg_parser().parse_args(argv)
    if args.list_checks:
        catalogue()
        return 0
    if args.export_agent:
        return _export_agent(args.export_agent)
    if args.hook:
        try:
            return remote.start_hook(args.hook_port, args.hook_token,
                                     args.hook_dir)
        except RemoteError as exc:
            say("red", "Webhook error: %s" % exc)
            return 2
    if args.no_local and not (args.windows or args.windows_import):
        say("red", "--no-local requires a Windows target (--windows or "
                   "--windows-import).")
        return 2
    try:
        return run_audit(args)
    except KeyboardInterrupt:
        say("red", "\nInterrupted.")
        return 2
    except Exception:
        say("red", "Fatal error:\n%s" % traceback.format_exc())
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(2)
    except BrokenPipeError:
        # e.g. `hooky.py checks | head` closed the pipe early
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
