#!/usr/bin/env python3
"""Hooky - Packages, Patching & Known-CVE audit module (PK-xxx)."""

import os
import re
from datetime import datetime
from .core import (register, Finding, secure_finding, skipped_finding,
                   info_finding, read_file, cap_lines, vercmp, sanitize,
                   CVE_DB_DATE, BACKPORT_CAVEAT)

CATEGORY = "Packages & Known CVEs"

# ---------------------------------------------------------------------------- #
# Built-in offline CVE signature database (snapshot %s).
# rule: affected if  version >= min (optional)  and  version < fixed
# ---------------------------------------------------------------------------- #
CVE_DB = {
    "sudo": [
        {"cve": "CVE-2021-3156", "name": "Baron Samedit - heap buffer overflow in "
         "sudoedit argument parsing", "fixed": "1.9.5p2", "sev": "HIGH", "score": 7.8,
         "rem": "Upgrade sudo to >= 1.9.5p2 (or the vendor's patched package)."},
        {"cve": "CVE-2019-14287", "name": "sudo UID bypass when Runas user is "
         "specified as -1 or '#-1'", "fixed": "1.8.28", "sev": "HIGH", "score": 7.8,
         "rem": "Upgrade sudo to >= 1.8.28 / 1.9.x and audit sudoers Runas rules."},
    ],
    "policykit-1": [
        {"cve": "CVE-2021-4034", "name": "PwnKit - pkexec local privilege "
         "escalation via environment injection", "fixed": "0.120", "sev": "HIGH",
         "score": 7.8,
         "rem": "Upgrade policykit-1 to the vendor-patched package; as interim "
         "mitigation remove the SUID bit: 'chmod 0755 /usr/bin/pkexec'."},
    ],
    "openssh-server": [
        {"cve": "CVE-2023-38408", "name": "ssh-agent forwarding remote code "
         "execution via PKCS#11", "min": "1.0", "fixed": "9.3p2", "sev": "CRITICAL",
         "score": 9.8,
         "rem": "Upgrade OpenSSH to >= 9.3p2 (vendor patched release)."},
        {"cve": "CVE-2024-6387", "name": "regreSSHion - signal-handler race "
         "leading to unauthenticated remote code execution", "min": "8.5p1",
         "fixed": "9.8p1", "sev": "HIGH", "score": 8.1,
         "rem": "Upgrade OpenSSH to >= 9.8p1; interim: set LoginGraceTime 0 (at "
         "availability cost) and restrict SSH exposure."},
        {"cve": "CVE-2018-15473", "name": "username enumeration via malformed "
         "public-key auth responses", "fixed": "7.8", "sev": "MEDIUM", "score": 5.3,
         "rem": "Upgrade OpenSSH to >= 7.8 (vendor patched release)."},
    ],
    "curl": [
        {"cve": "CVE-2023-38545", "name": "SOCKS5 proxy handshake heap buffer "
         "overflow (curl & libcurl)", "fixed": "8.4.0", "sev": "HIGH", "score": 8.8,
         "rem": "Upgrade curl/libcurl to >= 8.4.0 (vendor patched release)."},
    ],
    "bash": [
        {"cve": "CVE-2014-6271", "name": "Shellshock - CGIs and scripts invoking "
         "bash with crafted environment", "fixed": "4.3", "sev": "CRITICAL",
         "score": 10.0,
         "rem": "Upgrade bash to a vendor-patched release (>= 4.3 with distro "
         "patches)."},
    ],
    "zlib": [
        {"cve": "CVE-2018-25032", "name": "memory corruption in deflate on large "
         "windows", "fixed": "1.2.12", "sev": "HIGH", "score": 7.4,
         "rem": "Upgrade zlib to >= 1.2.12 (vendor patched release)."},
    ],
    "glibc": [
        {"cve": "CVE-2015-0235", "name": "GHOST - gethostbyname heap overflow",
         "fixed": "2.18", "sev": "HIGH", "score": 8.1,
         "rem": "Upgrade glibc to >= 2.18 (vendor patched release) and reboot."},
    ],
    "liblog4j2-java": [
        {"cve": "CVE-2021-44228", "name": "Log4Shell - remote code execution via "
         "JNDI lookup in logged strings", "fixed": "2.15.0", "sev": "CRITICAL",
         "score": 10.0,
         "rem": "Upgrade log4j-core to >= 2.17.1; interim: set "
         "-Dlog4j2.formatMsgNoLookups=true."},
    ],
}

EOL_TABLE = {
    ("ubuntu", "16.04"): "2021-04", ("ubuntu", "18.04"): "2023-05",
    ("ubuntu", "20.04"): "2025-04", ("ubuntu", "21.04"): "2022-01",
    ("ubuntu", "21.10"): "2022-07", ("ubuntu", "22.04"): "2027-04",
    ("ubuntu", "23.04"): "2024-01", ("ubuntu", "23.10"): "2024-07",
    ("ubuntu", "24.04"): "2029-04", ("ubuntu", "24.10"): "2025-07",
    ("ubuntu", "25.04"): "2026-01", ("ubuntu", "25.10"): "2026-07",
    ("debian", "9"): "2022-06", ("debian", "10"): "2024-06",
    ("debian", "11"): "2026-08", ("debian", "12"): "2028-06",
    ("debian", "13"): "2030-06",
    ("rhel", "8"): "2029-05", ("rhel", "9"): "2032-05",
    ("centos", "7"): "2024-06", ("centos", "8"): "2021-12",
    ("almalinux", "8"): "2029-05", ("almalinux", "9"): "2032-05",
    ("rocky", "8"): "2029-05", ("rocky", "9"): "2032-05",
    ("amzn", "2"): "2026-06", ("amzn", "2023"): "2028-06",
    ("fedora", "38"): "2024-05", ("fedora", "39"): "2024-11",
    ("fedora", "40"): "2025-05", ("fedora", "41"): "2025-11",
    ("fedora", "42"): "2026-05", ("fedora", "43"): "2026-11",
}


# ---------------------------------------------------------------- PK-001
@register("PK-001", "Operating system end-of-life status", CATEGORY)
def check_os_eol(ctx):
    orl = {}
    data = read_file("/etc/os-release") or ""
    for line in data.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            orl[k.strip()] = v.strip().strip('"')
    distro_id = orl.get("ID", "").lower()
    ver = orl.get("VERSION_ID", "")
    pretty = orl.get("PRETTY_NAME", "unknown OS")
    key = (distro_id, ver)
    eol = EOL_TABLE.get(key)
    if eol is None:
        # tolerate "22.04.5" style versions
        base = ver.split(".")[0:2]
        if len(base) == 2:
            eol = EOL_TABLE.get((distro_id, ".".join(base)))
        if eol is None and distro_id.startswith("rhel"):
            eol = EOL_TABLE.get((distro_id, ver.split(".")[0]))
    today = datetime.utcnow().strftime("%Y-%m")
    if eol is None:
        return [info_finding(_eol_fn, "/etc/os-release",
                             "%s (no EOL mapping in Hooky's lifecycle table)"
                             % pretty,
                             "Hooky has no lifecycle entry for this exact "
                             "distribution/version. Verify end-of-life status "
                             "against the vendor's lifecycle page.",
                             "Track the vendor lifecycle page and plan upgrades "
                             "6 months before EOL.")]
    if today > eol:
        return [Finding("PK-001", _eol_fn.check_name, CATEGORY, "VULNERABLE",
                        "HIGH", 8.5, "/etc/os-release",
                        "%s - standard support ended %s (current month: %s)"
                        % (pretty, eol, today),
                        "The OS is past its end-of-support date. Security patches "
                        "for new CVEs are no longer published for the standard "
                        "channel, so every future vulnerability stays exploitable "
                        "on this host.",
                        "Plan an in-place or fresh upgrade to a supported release "
                        "immediately; as an interim, subscribe to the vendor's "
                        "extended support (e.g. Ubuntu ESM / Debian LTS) and verify "
                        "it is actually enabled.")]
    # months to EOL
    y, m = (int(x) for x in eol.split("-"))
    ty, tm = (int(x) for x in today.split("-"))
    months = (y - ty) * 12 + (m - tm)
    if months <= 6:
        return [Finding("PK-001", _eol_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 5.5, "/etc/os-release",
                        "%s - reaches end of standard support in ~%d month(s) (%s)"
                        % (pretty, max(months, 0), eol),
                        "The OS approaches end of support; after that date new "
                        "vulnerabilities receive no patches.",
                        "Schedule the upgrade to the next supported release now "
                        "and freeze new workloads on this OS version.")]
    return [secure_finding(_eol_fn, "/etc/os-release",
                           "%s - supported until %s (~%d months left)"
                           % (pretty, eol, months),
                           "The operating system is within its supported "
                           "lifecycle window.")]


_eol_fn = None


# ---------------------------------------------------------------- PK-002
@register("PK-002", "Pending security updates", CATEGORY)
def check_pending_updates(ctx):
    pkgs = ctx.installed_packages()
    if not pkgs:
        return [skipped_finding(_upd_fn, "package database",
                                "No dpkg/rpm package database available.")]
    rc, out, err = ctx.run(["apt-get", "-s", "upgrade"], timeout=90)
    inst_lines = []
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r"^Inst\s+(\S+)\s+\[", line)
            if m:
                inst_lines.append(line.strip())
    else:
        # fallback: apt list --upgradable
        rc2, out2, _ = ctx.run(["apt", "list", "--upgradable"], timeout=90)
        if rc2 == 0:
            for line in out2.splitlines()[1:]:
                m = re.match(r"^(\S+)/(\S+)\s+\[?(\S+)", line)
                if m:
                    inst_lines.append("Inst %s [%s]" % (m.group(1), m.group(3)))
    if not inst_lines:
        note = err.strip().splitlines()[-1] if err.strip() else ""
        return [info_finding(_upd_fn, "APT package index",
                             "upgrade simulation returned no pending updates.%s"
                             % ("\nNote: " + note if note else ""),
                             "No upgradable packages reported. If this host has "
                             "never run 'apt-get update', refresh the index first "
                             "and re-test.",
                             "Run 'sudo apt-get update && sudo apt-get upgrade' "
                             "regularly (see PK-005 for automation).")]
    sec = [l for l in inst_lines if "security" in l.lower()]
    ev, _ = cap_lines(sec or inst_lines, 15)
    if sec:
        return [Finding("PK-002", _upd_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 6.2, "APT repositories (security origin)",
                        "%d pending SECURITY updates:\n%s\n(%d upgradable in total)"
                        % (len(sec), ev, len(inst_lines)),
                        "Published security fixes are available but not installed. "
                        "The gap between 'fix released' and 'fix deployed' is "
                        "prime exploitation territory - attackers automate this "
                        "differential.",
                        "Apply now: 'sudo apt-get update && sudo apt-get upgrade' "
                        "(or unattended-upgrades, see PK-005). Reboot if the kernel "
                        "or core libraries were updated.")]
    return [Finding("PK-002", _upd_fn.check_name, CATEGORY, "VULNERABLE",
                    "LOW", 2.5, "APT repositories",
                    "%d upgradable packages (none from a security origin):\n%s"
                    % (len(inst_lines), ev),
                    "Only non-security updates are pending. Keeping packages "
                    "current reduces drift and surprise dependency chains during "
                    "the next security emergency.",
                    "Schedule a maintenance window: 'sudo apt-get upgrade'.")]


_upd_fn = None


# ---------------------------------------------------------------- PK-003
@register("PK-003", "Reboot required / running kernel outdated", CATEGORY)
def check_reboot_required(ctx):
    reboot_flag = os.path.exists("/var/run/reboot-required")
    running = ""
    try:
        import platform as _p
        running = _p.release()
    except Exception:
        pass
    pkgs = ctx.installed_packages()
    newest = None
    for name, ver in pkgs.items():
        if re.match(r"^linux-image-[\d.]+", name) or name in ("kernel", "kernel-core"):
            v = name.split("linux-image-")[-1].split("-")[0] if "linux-image-" in name else ver
            if newest is None or vercmp(v, newest) > 0:
                newest = v
    if reboot_flag:
        details = read_file("/var/run/reboot-required.pkgs") or ""
        return [Finding("PK-003", _rb_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 5.4, "/var/run/reboot-required",
                        "reboot-required flag present; packages pending reboot: %s"
                        % details.strip().replace("\n", ", "),
                        "Core libraries or the kernel were updated but the host "
                        "still runs the old in-memory versions. Runtime state and "
                        "patch level diverge until reboot.",
                        "Schedule a reboot at the next maintenance window to "
                        "activate the patched kernel/libraries.")]
    if newest and running and vercmp(newest, running.split("-")[0]) > 0 and \
            not running.startswith(newest):
        return [Finding("PK-003", _rb_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 5.4, "running kernel " + running,
                        "newest installed kernel image is %s; running kernel is %s"
                        % (newest, running),
                        "The host runs an older kernel than the newest installed "
                        "image, i.e. kernel patches are staged but inactive.",
                        "Reboot into the new kernel at the next maintenance "
                        "window.")]
    note = ("running kernel %s; no reboot flag, no newer kernel image installed"
            % (running or "unknown")) if running else \
           "no reboot flag present (kernel comparison unavailable in this environment)"
    return [secure_finding(_rb_fn, "kernel", note,
                           "Running kernel matches the newest installed image; no "
                           "reboot is pending.")]


_rb_fn = None


# ---------------------------------------------------------------- PK-004
@register("PK-004", "Known CVE matches in installed package versions", CATEGORY)
def check_cve_matches(ctx):
    pkgs = ctx.installed_packages()
    if not pkgs:
        return [skipped_finding(_cve_fn, "package database",
                                "No dpkg/rpm package database available.")]
    out = []
    scanned = 0
    for pkg_name, rules in CVE_DB.items():
        if pkg_name not in pkgs:
            continue
        scanned += 1
        ver = pkgs[pkg_name]
        for rule in rules:
            mn = rule.get("min")
            fx = rule["fixed"]
            if mn and vercmp(ver, mn) < 0:
                continue
            if vercmp(ver, fx) >= 0:
                continue
            desc = ("%s - %s" % (rule["cve"], rule["name"]) +
                    "\n\n" + BACKPORT_CAVEAT.format(dbdate=CVE_DB_DATE, pkg=pkg_name))
            out.append(Finding("PK-004", _cve_fn.check_name, CATEGORY, "VULNERABLE",
                               rule["sev"], rule["score"],
                               "installed package '%s' version %s" % (pkg_name, ver),
                               "%s %s matches %s (fixed in >= %s%s)"
                               % (pkg_name, ver, rule["cve"], fx,
                                  "; introduced %s" % mn if mn else ""),
                               desc,
                               rule["rem"] + " Verify with the vendor advisory "
                               "(e.g. 'apt-get changelog %s' / security tracker) "
                               "whether this version already carries the backported "
                               "patch." % pkg_name))
    if out:
        out.sort(key=lambda f: -f.score)
    else:
        total = len(pkgs)
        return [secure_finding(_cve_fn, "installed packages (%d scanned)" % len(CVE_DB),
                               "no version in the %d-package signature set matched a "
                               "known-vulnerable range; %d packages installed in total"
                               % (len(CVE_DB), total),
                               "No matches against Hooky's offline CVE "
                               "signature database (snapshot %s). This complements, "
                               "but does not replace, a feed-based scanner."
                               % CVE_DB_DATE)]
    return out


_cve_fn = None


# ---------------------------------------------------------------- PK-005
@register("PK-005", "Automatic security updates not configured", CATEGORY)
def check_unattended(ctx):
    pkgs = ctx.installed_packages()
    installed = "unattended-upgrades" in pkgs
    cfg = read_file("/etc/apt/apt.conf.d/20auto-upgrades")
    if installed and cfg and "Unattended-Upgrade" in cfg and '"1"' in cfg:
        return [secure_finding(_unatt_fn, "/etc/apt/apt.conf.d/20auto-upgrades",
                               cfg.strip()[:200],
                               "unattended-upgrades is installed and enabled for "
                               "automatic security patching.")]
    if not installed:
        return [Finding("PK-005", _unatt_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 4.8, "package database + /etc/apt/apt.conf.d/",
                        "package 'unattended-upgrades' is not installed",
                        "Without automatic security patching, protection depends "
                        "entirely on manual discipline; in practice hosts lag weeks "
                        "or months behind published fixes.",
                        "Enable: 'sudo apt-get install unattended-upgrades && "
                        "sudo dpkg-reconfigure -plow unattended-upgrades'; verify "
                        "/etc/apt/apt.conf.d/20auto-upgrades contains "
                        "APT::Periodic::Unattended-Upgrade \"1\".")]
    return [Finding("PK-005", _unatt_fn.check_name, CATEGORY, "VULNERABLE",
                    "MEDIUM", 4.8, "/etc/apt/apt.conf.d/20auto-upgrades",
                    "unattended-upgrades installed but auto-upgrade not enabled "
                    "(config: %s)" % (cfg.strip()[:120] if cfg else "(config absent)"),
                    "The package is present but automatic application of security "
                    "updates is switched off.",
                    "Set 'APT::Periodic::Update-Package-Lists \"1\";' and "
                    "'APT::Periodic::Unattended-Upgrade \"1\";' in "
                    "/etc/apt/apt.conf.d/20auto-upgrades.")]


_unatt_fn = None


# ---------------------------------------------------------------- PK-006
@register("PK-006", "Development toolchain present", CATEGORY)
def check_dev_tools(ctx):
    pkgs = ctx.installed_packages()
    dev = [p for p in ("gcc", "g++", "make", "clang", "build-essential") if p in pkgs]
    if dev:
        ev = ", ".join("%s (%s)" % (p, pkgs[p]) for p in sorted(dev))
        return [info_finding(_dev_fn, "installed packages",
                             "development tools installed: %s" % ev,
                             "Compilers and build tooling let an attacker compile "
                             "kernel exploits and custom implants directly on the "
                             "host. On hardened production servers they are usually "
                             "absent.",
                             "If no build activity is expected on this host, remove "
                             "the toolchain: 'sudo apt-get purge gcc make ...' and "
                             "build artifacts in CI instead.")]
    return [secure_finding(_dev_fn, "installed packages",
                           "no compiler/build toolchain packages found",
                           "No local compilation capability for potential "
                           "post-exploitation payload building.")]


_dev_fn = None


# ---------------------------------------------------------------- PK-007
@register("PK-007", "Obsolete kernel images installed", CATEGORY)
def check_old_kernels(ctx):
    pkgs = ctx.installed_packages()
    imgs = sorted(n for n in pkgs if n.startswith("linux-image-"))
    if len(imgs) <= 1:
        if not imgs:
            return [info_finding(_old_fn, "package database",
                                 "no linux-image packages found (container or "
                                 "shared-host-kernel environment)",
                                 "Kernel packages are managed on the container/VM "
                                 "host; keep the HOST kernel patched instead.")]
        return [secure_finding(_old_fn, "package database",
                               "only one kernel image installed: %s" % imgs[0],
                               "No stale kernel images accumulate on disk.")]
    return [info_finding(_old_fn, "installed packages",
                         "%d kernel images installed:\n%s" % (len(imgs), "\n".join(imgs[:10])),
                         "Multiple kernel images are installed. Keeping the "
                         "current and one previous image is sensible for rollback; "
                         "older ones waste space and keep vulnerable code recoverable "
                         "from disk (data forensics / dual-boot abuse).",
                         "Purge kernels older than the previous one: 'sudo apt-get "
                         "autoremove --purge' after confirming the running kernel.")]


_old_fn = None


# module-level aliases used inside the check functions
_eol_fn = check_os_eol
_upd_fn = check_pending_updates
_rb_fn = check_reboot_required
_cve_fn = check_cve_matches
_unatt_fn = check_unattended
_dev_fn = check_dev_tools
_old_fn = check_old_kernels

CHECKS = [check_os_eol, check_pending_updates, check_reboot_required,
          check_cve_matches, check_unattended, check_dev_tools, check_old_kernels]
