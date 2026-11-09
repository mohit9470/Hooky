#!/usr/bin/env python3
"""Hooky - Enterprise & Compliance audit module (EC-xxx).

The controls large organisations are audited against (CIS Benchmarks, PCI DSS,
ISO/IEC 27001, NIST SP 800-53 families): security logging/auditd, time
synchronisation, centralised log shipping, legal login banner, password
aging policy, sudo command logging, core-dump restriction and removable
(USB) storage policy.

Every check is read-only and degrades gracefully without root: tests that
need privileged files are marked SKIPPED with the exact reason. Results
collected from inside a container are annotated, because kernel-level and
service-level state may be managed by the host.
"""

import glob
import os
import re

from .core import (register, Finding, secure_finding, info_finding,
                   skipped_finding, read_file, parse_kv_file, read_sysctl)

EC = "Enterprise & Compliance"

_CONTAINER = (os.path.exists("/.dockerenv")
              or os.path.exists("/run/.containerenv"))
_CONT_NOTE = ("Note: running inside a container - confirm this control on "
              "the container host as well. " if _CONTAINER else "")


def _f(fn, status, sev, score, loc, ev, desc, rem):
    return Finding(fn.check_id, fn.check_name, fn.check_category,
                   status, sev, score, loc, ev, desc, rem)


def _proc_running(ctx, names):
    """True when any process whose argv contains one of `names` is running.

    Uses pgrep when available and falls back to scanning /proc cmdlines.
    """
    pat = "|".join(re.escape(n) for n in names)
    rc, _out, _err = ctx.run(["pgrep", "-f", r"(%s)" % pat], timeout=10)
    if rc == 0:
        return True
    if rc not in (1, 127):        # 1 = no match (pgrep works), 127 = missing
        return False
    for status_path in glob.glob("/proc/[0-9]*/cmdline")[:2000]:
        data = ctx.cat(status_path, max_bytes=4096)
        if data:
            argv0 = data.split("\x00")[0]
            if any(n in argv0 or n in data for n in names):
                return True
    return False


# --------------------------------------------------------------------------- #
#  EC-001 - audit framework
# --------------------------------------------------------------------------- #

@register("EC-001", "Audit framework (auditd) installed and running", EC)
def check_auditd(ctx):
    conf = ctx.cat("/etc/audit/auditd.conf")
    rc, out, _ = ctx.run(["pgrep", "-x", "auditd"], timeout=10)
    running = (rc == 0)
    if not running and rc in (1, 127):
        running = _proc_running(ctx, ["auditd"])
    rules = os.path.exists("/etc/audit/rules.d") or os.path.exists("/etc/audit/audit.rules")
    installed = bool(conf) or rules or running or \
        bool(ctx.run(["sh", "-c", "command -v auditd"], timeout=5)[0] == 0)
    if running:
        return [secure_finding(
            check_auditd, "/etc/audit/auditd.conf",
            "auditd process is running%s" % ("; configuration present" if conf
                                             else ""),
            _CONT_NOTE + "Security event logging is active (CIS 4.1.x, "
            "PCI DSS Requirement 10).")]
    if installed and not running:
        return [_f(check_auditd, "VULNERABLE", "HIGH", 6.8,
                   "/etc/audit/auditd.conf",
                   "auditd is installed but the process is NOT running.",
                   _CONT_NOTE + "The audit framework exists but collects no "
                   "events. Security-relevant actions (privilege use, package "
                   "changes, auth attempts) leave no trace, which breaks the "
                   "logging requirements found in PCI DSS Req. 10, ISO/IEC "
                   "27001 A.8.15 and CIS Benchmark section 4.",
                   "1. sudo systemctl enable --now auditd\n"
                   "2. Verify events are collected:  sudo auditctl -l\n"
                   "3. Ship /var/log/audit/audit.log to your central SIEM.")]
    return [_f(check_auditd, "VULNERABLE", "HIGH", 7.1,
               "auditd (package auditd / audit service)",
               "No audit daemon, configuration or rules directory found "
               "(/etc/audit/auditd.conf missing).",
               _CONT_NOTE + "There is no kernel-level audit trail. Corporate "
               "compliance frameworks (PCI DSS Req. 10.2, ISO/IEC 27001 "
               "A.8.15, CIS Benchmark 4.1) require security-relevant events "
               "to be recorded; without auditd an incident investigation "
               "cannot reconstruct what happened on this host.",
               "1. Install the audit daemon:\n"
               "   Debian/Ubuntu: sudo apt-get install auditd audispd-plugins\n"
               "   RHEL-family:   sudo dnf install audit auditd-plugins\n"
               "2. Enable a CIS-style baseline in /etc/audit/rules.d/ "
               "(identity, logins, sessions, perm_mod, privileged commands).\n"
               "3. sudo systemctl enable --now auditd && sudo augenrules --load")]


# --------------------------------------------------------------------------- #
#  EC-002 - time synchronisation
# --------------------------------------------------------------------------- #

@register("EC-002", "Time synchronisation (NTP/chrony) configured", EC)
def check_time_sync(ctx):
    daemons = ["chronyd", "ntpd", "systemd-timesyncd", "ntpsec", "openntpd"]
    running = _proc_running(ctx, daemons)
    confs = [p for p in ("/etc/chrony/chrony.conf", "/etc/chrony.conf",
                         "/etc/ntp.conf", "/etc/ntpsec/ntp.conf",
                         "/etc/systemd/timesyncd.conf") if os.path.exists(p)]
    if running:
        ev = "sync daemon running (%s)%s" % (
            "config: " + ", ".join(confs) if confs else "",
            "")
        return [secure_finding(check_time_sync, ", ".join(confs) or "ntp/chrony",
                               ev.strip(),
                               _CONT_NOTE + "Clock is synchronised - log "
                               "timestamps stay comparable across systems "
                               "(PCI DSS Req. 10.6, ISO/IEC 27001 A.8.17).")]
    if confs:
        return [_f(check_time_sync, "VULNERABLE", "LOW", 3.6,
                   confs[0],
                   "Time sync configuration exists (%s) but no sync daemon "
                   "appears to be running." % ", ".join(confs),
                   _CONT_NOTE + "Clock drift makes log correlation between "
                   "hosts and SIEM correlation rules unreliable, and breaks "
                   "Kerberos/AD authentication (max 5 min tolerance).",
                   "1. sudo systemctl enable --now chronyd   # or chrony / ntp\n"
                   "2. Verify:  chronyc tracking")]
    return [_f(check_time_sync, "VULNERABLE", "MEDIUM", 5.0,
               "chrony / ntp / systemd-timesyncd",
               "No time synchronisation daemon or configuration found.",
               _CONT_NOTE + "Without a common time source, audit-log "
               "timestamps from this host cannot be correlated with other "
               "systems - a hard requirement in every enterprise logging "
               "standard (PCI DSS Req. 10.6, ISO/IEC 27001 A.8.17, CIS 2.1). "
               "Kerberos and domain authentication also fail with drift.",
               "1. Install and enable chrony:\n"
               "   sudo apt-get install chrony     # Debian/Ubuntu\n"
               "   sudo dnf install chrony         # RHEL-family\n"
               "2. Point it at your corporate NTP servers in "
               "/etc/chrony/chrony.conf (or use the AD domain controllers).\n"
               "3. sudo systemctl enable --now chronyd && chronyc tracking")]


# --------------------------------------------------------------------------- #
#  EC-003 - central log shipping
# --------------------------------------------------------------------------- #

_FWD_RE = re.compile(
    r"(@@|\*\.@\w*@|action\s*\(\s*type\s*=\s*[\"']omfwd|^\s*\*\s*@@?)", re.I)


@register("EC-003", "Central log shipping to a remote log host / SIEM", EC)
def check_log_shipping(ctx):
    hit_lines, scanned = [], []
    paths = ["/etc/rsyslog.conf", "/etc/syslog-ng/syslog-ng.conf",
             "/etc/filebeat/filebeat.yml", "/etc/vector/vector.toml",
             "/etc/fluent-bit/fluent-bit.conf", "/etc/datadog-agent/datadog.yaml"]
    paths += sorted(glob.glob("/etc/rsyslog.d/*.conf"))
    for p in paths:
        if not os.path.exists(p):
            continue
        scanned.append(p)
        data = read_file(p, max_bytes=131072) or ""
        for ln in data.splitlines():
            s = ln.strip()
            if s.startswith("#"):
                continue
            if (re.search(r"@@[\w.\-]+:\d+", ln) or
                re.search(r"action\s*\(\s*type\s*=\s*[\"']omfwd", ln, re.I) or
                re.search(r"@\w+[\w.\-]*:\d+", ln) or
                (p.endswith(".yml") and re.search(r"(hosts|output\.logstash|logstash)", ln, re.I))):
                hit_lines.append("%s: %s" % (p, s[:120]))
                break
    shipper_running = _proc_running(ctx, ["filebeat", "fluentd", "fluent-bit",
                                          "vector", "nxlog", "splunk",
                                          "cloud-watch-agent", "amazon-cloudwatch-agent"])
    if hit_lines or (shipper_running and scanned):
        ev = "\n".join(hit_lines[:6]) or "a log shipper agent process is running"
        return [secure_finding(check_log_shipping,
                               ", ".join(scanned) or "log shipper agent",
                               ev,
                               _CONT_NOTE + "Logs are forwarded to a central "
                               "system (PCI DSS Req. 10.5.1, ISO/IEC 27001 "
                               "A.8.15).")]
    if not scanned and not shipper_running:
        return [_f(check_log_shipping, "VULNERABLE", "MEDIUM", 5.4,
                   "/etc/rsyslog.conf (missing)",
                   "No rsyslog/syslog-ng configuration and no log shipper "
                   "(filebeat/fluentd/vector/...) found.",
                   _CONT_NOTE + "All logs exist only on this host. An "
                   "attacker with root can delete them, a disk failure loses "
                   "them, and the SIEM receives nothing - violating central "
                   "logging requirements (PCI DSS Req. 10.5.1, ISO/IEC 27001 "
                   "A.8.15, CIS 4.2).",
                   "1. Forward to your log host in /etc/rsyslog.d/90-remote.conf:\n"
                   "   *.* @@loghost.example.com:514        (TCP)\n"
                   "   or action(type=\"omfwd\" target=\"loghost.example.com\" port=\"514\" protocol=\"tcp\")\n"
                   "2. Or deploy the corporate shipper agent (Filebeat/Fluent Bit/Vector).\n"
                   "3. sudo systemctl restart rsyslog")]
    return [_f(check_log_shipping, "VULNERABLE", "MEDIUM", 5.4,
               ", ".join(scanned),
               "syslog is configured but no remote forwarding target and no "
               "shipper agent was detected - logs stay on this host only.",
               _CONT_NOTE + "Without remote forwarding, an attacker with "
               "root privileges can wipe the local evidence (PCI DSS Req. "
               "10.5.1 requires log protection; enterprise policy requires "
               "off-host retention).",
               "1. Add a forwarding rule to /etc/rsyslog.d/90-remote.conf:\n"
               "   *.* @@siem.example.com:514\n"
               "2. Or install the corporate log shipper and target the SIEM.\n"
               "3. sudo systemctl restart rsyslog")]


# --------------------------------------------------------------------------- #
#  EC-004 - legal login banner
# --------------------------------------------------------------------------- #

_BANNER_RE = re.compile(
    r"authori[sz]ed|warning|notice|monitored|prosecut|no expect|consent", re.I)


@register("EC-004", "Legal warning banner for network logins (/etc/issue.net)", EC)
def check_banner(ctx):
    data = ctx.cat("/etc/issue.net")
    if data is None or not data.strip():
        return [_f(check_banner, "VULNERABLE", "LOW", 3.1,
                   "/etc/issue.net",
                   "File is missing or empty.",
                   _CONT_NOTE + "Users connecting over SSH (or other network "
                   "logins) receive no 'authorised use only' warning before "
                   "authentication. Corporate policies and ISO/IEC 27001 "
                   "A.6.2 expect a legal notice that establishes the terms "
                   "of use and supports prosecution of misuse.",
                   "1. Create /etc/issue.net with your corporate warning, e.g.:\n"
                   "   *** AUTHORISED ACCESS ONLY ***\n"
                   "   All connections are logged and monitored. Unauthorised\n"
                   "   access will be prosecuted to the full extent of the law.\n"
                   "2. For SSH also set 'Banner /etc/issue.net' in "
                   "/etc/ssh/sshd_config and reload sshd.")]
    if _BANNER_RE.search(data):
        return [secure_finding(check_banner, "/etc/issue.net",
                               data.strip()[:200],
                               _CONT_NOTE + "A legal warning banner is "
                               "present for network logins.")]
    return [_f(check_banner, "VULNERABLE", "LOW", 3.0,
               "/etc/issue.net",
               "Banner contains only OS/default text (no authorised-use "
               "wording): %r" % data.strip()[:120],
               _CONT_NOTE + "The default OS banner provides no legal warning "
               "before login. Many corporate policies (and ISO/IEC 27001 "
               "A.6.2) require an explicit authorised-use notice.",
               "1. Replace /etc/issue.net with the corporate warning banner.\n"
               "2. Ensure sshd_config uses it: 'Banner /etc/issue.net'.")]


# --------------------------------------------------------------------------- #
#  EC-005 - password aging policy
# --------------------------------------------------------------------------- #

@register("EC-005", "Password aging policy (login.defs PASS_MAX_DAYS)", EC)
def check_password_aging(ctx):
    kv = parse_kv_file("/etc/login.defs")
    if kv is None:
        return [skipped_finding(check_password_aging, "/etc/login.defs",
                                "Cannot read /etc/login.defs from this "
                                "account (permission denied).")]
    val = kv.get("PASS_MAX_DAYS")
    days = int(val) if (val or "").isdigit() else None
    if days is None:
        return [_f(check_password_aging, "VULNERABLE", "MEDIUM", 4.2,
                   "/etc/login.defs:PASS_MAX_DAYS",
                   "PASS_MAX_DAYS is not set in /etc/login.defs.",
                   _CONT_NOTE + "Without a maximum password age, accounts "
                   "created without per-user overrides keep their password "
                   "forever - a leaked credential stays valid indefinitely.",
                   "1. Edit /etc/login.defs:\n"
                   "   PASS_MAX_DAYS   90\n"
                   "   PASS_MIN_DAYS   1\n"
                   "   PASS_WARN_AGE   14\n"
                   "2. Fix existing accounts:  sudo chage --maxdays 90 <user>")]
    if days > 90:
        return [_f(check_password_aging, "VULNERABLE",
                   "HIGH" if days > 365 else "MEDIUM",
                   6.9 if days > 365 else 4.8,
                   "/etc/login.defs:PASS_MAX_DAYS",
                   "PASS_MAX_DAYS %d" % days,
                   _CONT_NOTE + "Passwords may be used %d days (%s). A "
                   "credential that leaks today remains valid for that "
                   "long." % (days, "> 1 year" if days > 365 else "> 90 days"),
                   "1. Set 'PASS_MAX_DAYS 90' in /etc/login.defs.\n"
                   "2. Apply to existing accounts:  sudo chage --maxdays 90 <user>")]
    return [secure_finding(check_password_aging, "/etc/login.defs",
                           "PASS_MAX_DAYS %s (<= 90)" % val,
                           _CONT_NOTE + "Default password age is within the "
                           "90-day corporate baseline.")]


# --------------------------------------------------------------------------- #
#  EC-006 - sudo command logging
# --------------------------------------------------------------------------- #

@register("EC-006", "sudo command logging enabled", EC)
def check_sudo_logging(ctx):
    sudoers = ctx.cat("/etc/sudoers")
    if sudoers is None:
        return [skipped_finding(check_sudo_logging, "/etc/sudoers",
                                "/etc/sudoers is root-only (0400/0440) and "
                                "this audit ran unprivileged - re-run with "
                                "sudo to test this control.")]
    lines = [sudoers]
    for p in sorted(glob.glob("/etc/sudoers.d/*")):
        d = ctx.cat(p)
        if d:
            lines.append(d)
    text = "\n".join(lines)
    hits = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("#") or not s:
            continue
        if re.search(r"Defaults\s+.*(logfile|iolog_dir|journal_cmd|sudoers_log)", ln):
            hits.append(s[:120])
    if hits:
        return [secure_finding(check_sudo_logging,
                               "/etc/sudoers (Defaults)",
                               "; ".join(hits[:4]),
                               "Every sudo use is logged to a dedicated file.")]
    return [_f(check_sudo_logging, "VULNERABLE", "LOW", 3.5,
               "/etc/sudoers",
               "No 'Defaults logfile=' (or iolog_dir) directive found in "
               "/etc/sudoers or /etc/sudoers.d/.",
               "Privilege escalation via sudo happens, but is recorded only "
               "in the generic auth log without the full command line. "
               "Enterprise baselines (CIS 5.2.x, PCI DSS Req. 10.2.2) require "
               "individual privileged-command logging.",
               "1. Add to /etc/sudoers (visudo):\n"
               "   Defaults logfile=\"/var/log/sudo.log\"\n"
               "   Defaults log_input, log_output\n"
               "2. Ship /var/log/sudo.log to the SIEM.")]


# --------------------------------------------------------------------------- #
#  EC-007 - core dump restriction
# --------------------------------------------------------------------------- #

@register("EC-007", "Core dumps restricted (fs.suid_dumpable)", EC)
def check_core_dumps(ctx):
    val = read_sysctl(ctx, "fs.suid_dumpable")
    if val is None:
        return [skipped_finding(check_core_dumps,
                                "/proc/sys/fs/suid_dumpable",
                                "Kernel parameter fs.suid_dumpable could "
                                "not be read in this environment.")]
    if val == "0":
        return [secure_finding(check_core_dumps,
                               "/proc/sys/fs/suid_dumpable",
                               "fs.suid_dumpable = 0 (core dumps of "
                               "setuid binaries disabled)",
                               _CONT_NOTE + "Crash dumps cannot leak "
                               "password material from privileged processes "
                               "(CIS 1.5.3).")]
    return [_f(check_core_dumps, "VULNERABLE", "MEDIUM", 4.6,
               "/proc/sys/fs/suid_dumpable",
               "fs.suid_dumpable = %s" % val,
               _CONT_NOTE + "Privileged (setuid) processes may write core "
               "dumps. A crafted crash turns into a full memory dump of a "
               "root process, frequently containing hashes, keys and "
               "tickets (CIS Benchmark 1.5.3 flags this as fail).",
               "1. Set in /etc/sysctl.d/99-secure.conf:  fs.suid_dumpable = 0\n"
               "2. Apply:  sudo sysctl --system\n"
               "3. For systemd hosts also set Storage=none in "
               "/etc/systemd/coredump.conf.d/ and run "
               "'sudo systemctl daemon-reload'.")]


# --------------------------------------------------------------------------- #
#  EC-008 - removable USB storage policy
# --------------------------------------------------------------------------- #

@register("EC-008", "USB mass-storage driver blocked (data-exfiltration control)", EC)
def check_usb_storage(ctx):
    loaded = os.path.exists("/sys/module/usb_storage") or \
        os.path.exists("/sys/module/uas")
    blocked = []
    for p in sorted(glob.glob("/etc/modprobe.d/*.conf")):
        data = ctx.cat(p) or ""
        for ln in data.splitlines():
            s = ln.strip()
            if re.match(r"blacklist\s+(usb-storage|uas)\b", s) or \
               re.match(r"install\s+(usb-storage|uas)\s+/bin/(false|true)", s):
                blocked.append("%s: %s" % (p, s))
    if blocked:
        return [secure_finding(check_usb_storage,
                               ", ".join(b.split(":")[0] for b in blocked),
                               "\n".join(blocked[:5]),
                               _CONT_NOTE + "USB mass-storage is blocked by "
                               "kernel policy - a standard enterprise "
                               "data-exfiltration control.")]
    if loaded:
        return [_f(check_usb_storage, "VULNERABLE", "LOW", 3.3,
                   "/sys/module/usb_storage",
                   "usb-storage driver is loaded and no modprobe blacklist "
                   "policy exists.",
                   _CONT_NOTE + "Any user can plug a USB disk and copy data "
                   "or introduce malware. Corporate data-loss-prevention "
                   "baselines require removable media to be disabled unless "
                   "explicitly approved.",
                   "1. Create /etc/modprobe.d/usb-block.conf:\n"
                   "   blacklist usb-storage\n"
                   "   install usb-storage /bin/false\n"
                   "   blacklist uas\n"
                   "2. Rebuild initramfs if usb-storage is built in: "
                   "sudo update-initramfs -u (Debian) / dracut -f (RHEL).\n"
                   "3. Reboot or: sudo modprobe -r usb-storage uas")]
    return [info_finding(
        check_usb_storage, "/sys/module/usb_storage",
        "USB storage is not loaded and not explicitly blacklisted.",
        _CONT_NOTE + "The driver is simply unused right now. Enterprises "
        "usually block it explicitly so it cannot be loaded later by an "
        "attacker with root.",
        "1. Create /etc/modprobe.d/usb-block.conf:\n"
        "   blacklist usb-storage\n"
        "   install usb-storage /bin/false\n"
        "2. Reboot for the change to take full effect.")]


CHECKS = [check_auditd, check_time_sync, check_log_shipping, check_banner,
          check_password_aging, check_sudo_logging, check_core_dumps,
          check_usb_storage]
