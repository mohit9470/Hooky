#!/usr/bin/env python3
"""Hooky - System Hardening audit module (HS-xxx)."""

import os
from .core import (register, Finding, secure_finding, skipped_finding,
                   info_finding, parse_kv_file, read_sysctl, mode_str,
                   is_world_writable, is_group_writable, is_world_readable,
                   has_sticky, is_suid, is_sgid, owner_names, cap_lines, sanitize)

CATEGORY = "System Hardening"


# ---------------------------------------------------------------- HS-001
@register("HS-001", "SUID/SGID binary inventory & placement", CATEGORY)
def check_suid_inventory(ctx):
    files = ctx.find("-type f \\( -perm -4000 -o -perm -2000 \\)", max_results=4000)
    std_prefixes = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib",
                    "/usr/libexec", "/usr/local/bin", "/usr/local/sbin")
    unusual = [p for p in files
               if not p.startswith(std_prefixes) and "/libexec/" not in p]
    listing, total = cap_lines(sorted(files), 25)
    if unusual:
        ulist, _ = cap_lines(sorted(unusual), 15)
        return [Finding("HS-001", _suid_fn.check_name, CATEGORY, "VULNERABLE",
                        "LOW", 2.1, unusual[0],
                        "%d SUID/SGID binaries found; %d in non-standard locations:\n%s"
                        % (total, len(unusual), ulist),
                        "SUID/SGID binaries outside standard system directories are "
                        "unusual and are a classic persistence / privilege-escalation "
                        "vector. Attackers deliberately place SUID copies of shells in "
                        "writable locations. Verify that every listed binary is "
                        "intentional and vendor-provided.",
                        "Review each listed binary. Remove unexpected SUID bits with "
                        "'sudo chmod u-s <file>' (or 'g-s' for SGID). If the binary is "
                        "unknown, quarantine it and investigate the host for compromise.")]
    return [info_finding(_suid_fn, "filesystem-wide",
                         "%d SUID/SGID binaries found, all in standard system paths:\n%s"
                         % (total, listing),
                         "All SUID/SGID binaries reside in standard system "
                         "directories. This inventory is the expected baseline.",
                         "Periodically compare this inventory against the baseline "
                         "(e.g. 'find / -xdev -type f -perm -4000'). Investigate any drift.")]


_suid_fn = None


# ---------------------------------------------------------------- HS-002
@register("HS-002", "World-writable SUID/SGID executables", CATEGORY)
def check_ww_suid(ctx):
    files = ctx.find("-type f \\( -perm -4000 -o -perm -2000 \\) -perm -0002",
                     max_results=200)
    if not files:
        return [secure_finding(_self_fn, "filesystem-wide",
                               "find -type f \\( -perm -4000 -o -perm -2000 \\) "
                               "-perm -0002 returned no results",
                               "No world-writable SUID/SGID executable exists. "
                               "Such a file would allow any user to gain root.")]
    out = []
    for path in files[:10]:
        st = ctx.stat(path)
        meta = "(mode %s, owner %s)" % (mode_str(st), owner_names(st)) if st else ""
        out.append(Finding("HS-002", _self_fn.check_name, CATEGORY, "VULNERABLE",
                           "CRITICAL", 9.1, path,
                           "world-writable SUID/SGID binary %s" % meta,
                           "A world-writable file with the SUID or SGID bit set can "
                           "be modified (replaced) by any local user and then "
                           "executed with elevated privileges. This is equivalent "
                           "to giving every user root access.",
                           "Immediately remove the writable permission or the SUID "
                           "bit: 'sudo chmod o-w <file>' and 'sudo chmod u-s <file>'. "
                           "Investigate how the file became world-writable - this "
                           "pattern is a common rootkit/implant indicator."))
    if len(files) > 10:
        out[-1].evidence += "\n... (%d more world-writable SUID/SGID files)" % (len(files) - 10)
    return out


_self_fn = None  # set at import end


# ---------------------------------------------------------------- HS-003
@register("HS-003", "World-writable files", CATEGORY)
def check_world_writable_files(ctx):
    files = ctx.find("-type f -perm -0002", max_results=5000)
    if not files:
        return [secure_finding(_wwf_fn, "filesystem-wide",
                               "find -type f -perm -0002 returned no results",
                               "No world-writable files were found on local real "
                               "filesystems.")]
    out = []
    shown = files[:15]
    for path in shown:
        st = ctx.stat(path)
        meta = "(mode %s, owner %s)" % (mode_str(st), owner_names(st)) if st else ""
        out.append(Finding("HS-003", _wwf_fn.check_name, CATEGORY, "VULNERABLE",
                           "HIGH", 7.5, path,
                           "world-writable file %s" % meta,
                           "Any local user (or any service account that is "
                           "compromised) can modify, replace or plant malware in a "
                           "world-writable file. If the file is executed, sourced or "
                           "read by a privileged process this becomes a privilege "
                           "escalation path.",
                           "Restrict the file: 'sudo chmod o-w <file>'. If the file "
                           "must stay shared, place it in a directory with the "
                           "sticky bit and grant write access to a dedicated group "
                           "instead of everyone."))
    if len(files) > 15:
        out.append(Finding("HS-003", _wwf_fn.check_name, CATEGORY, "VULNERABLE",
                           "HIGH", 7.5, shown[-1] if shown else "filesystem-wide",
                           "+ %d additional world-writable files beyond the %d shown"
                           % (len(files) - 15, 15),
                           "The scan found more world-writable files than are "
                           "displayed here; the aggregate exposure is the same.",
                           "Run 'sudo find / -xdev -type f -perm -0002 -ls' to "
                           "enumerate and remediate the remaining files."))
    return out


_wwf_fn = None


# ---------------------------------------------------------------- HS-004
@register("HS-004", "World-writable directories without sticky bit", CATEGORY)
def check_world_writable_dirs(ctx):
    dirs = ctx.find("-type d -perm -0002 ! -perm -1000", max_results=2000)
    if not dirs:
        return [secure_finding(_wwd_fn, "filesystem-wide",
                               "find -type d -perm -0002 ! -perm -1000 returned "
                               "no results",
                               "Every world-writable directory carries the sticky "
                               "bit (t), which prevents users from deleting or "
                               "renaming each other's files.")]
    out = []
    for path in dirs[:15]:
        st = ctx.stat(path)
        meta = "(mode %s, owner %s)" % (mode_str(st), owner_names(st)) if st else ""
        out.append(Finding("HS-004", _wwd_fn.check_name, CATEGORY, "VULNERABLE",
                           "MEDIUM", 5.5, path,
                           "world-writable directory without sticky bit %s" % meta,
                           "In a world-writable directory without the sticky bit any "
                           "user can delete or replace other users' files. This "
                           "enables denial-of-service and file-swap attacks against "
                           "scripts or data consumed by privileged processes.",
                           "Either remove world-write access ('sudo chmod o-w <dir>') "
                           "or add the sticky bit ('sudo chmod +t <dir>'), as used "
                           "on /tmp (mode 1777)."))
    if len(dirs) > 15:
        out[-1].evidence += "\n... (%d more directories)" % (len(dirs) - 15)
    return out


_wwd_fn = None


# ---------------------------------------------------------------- HS-005
@register("HS-005", "Files with no owner or no group", CATEGORY)
def check_unowned_files(ctx):
    files = ctx.find("\\( -type f -o -type d \\) \\( -nouser -o -nogroup \\)",
                     max_results=1000)
    if not files:
        return [secure_finding(_uno_fn, "filesystem-wide",
                               "find -nouser -o -nogroup returned no results",
                               "Every file and directory is mapped to a valid user "
                               "and group. Unowned files typically appear after "
                               "account deletion and are often taken over by an "
                               "attacker-created UID.")]
    lst, total = cap_lines(sorted(files), 12)
    return [Finding("HS-005", _uno_fn.check_name, CATEGORY, "VULNERABLE",
                    "MEDIUM", 4.6, files[0],
                    "%d unowned/ungrouped paths:\n%s" % (total, lst),
                    "Files whose UID/GID has no matching account are usually "
                    "leftovers from removed packages or deleted users. An attacker "
                    "who re-creates the deleted UID silently inherits all of these "
                    "files, including any sensitive data they contain.",
                    "Chown the files to a valid account ('sudo chown root:root <file>') "
                    "or remove them. Investigate whether the owning account was "
                    "deletion-authorised.")]


_uno_fn = None


# ---------------------------------------------------------------- HS-006
@register("HS-006", "Sensitive account database file permissions", CATEGORY)
def check_account_file_perms(ctx):
    specs = [
        ("/etc/passwd", 0o644, False),
        ("/etc/shadow", 0o640, True),
        ("/etc/group", 0o644, False),
        ("/etc/gshadow", 0o640, True),
    ]
    out, oks = [], []
    for path, max_mode, has_hashes in specs:
        st = ctx.stat(path)
        if st is None:
            oks.append("%s : not present" % path)
            continue
        mode = st.st_mode & 0o7777
        loc = "%s (mode %s, owner %s)" % (path, mode_str(st), owner_names(st))
        if is_world_writable(st) or is_group_writable(st):
            out.append(Finding("HS-006", _acct_fn.check_name, CATEGORY,
                               "VULNERABLE", "CRITICAL", 9.4, loc,
                               "account database is group/world-WRITABLE",
                               "A writable account database lets any local user "
                               "create accounts, elevate privileges or replace "
                               "password hashes.",
                               "Restore safe permissions immediately: "
                               "'sudo chown root:root <file> && sudo chmod 0644 "
                               "<file>' (shadow/gshadow: 0640)."))
        elif has_hashes and is_world_readable(st) and mode & 0o777 != 0 and (mode & 0o004):
            out.append(Finding("HS-006", _acct_fn.check_name, CATEGORY,
                               "VULNERABLE", "HIGH", 7.8, loc,
                               "password hash database is world-READABLE",
                               "World-readable password hashes allow offline "
                               "cracking (John/hashcat) of every account password "
                               "on the system.",
                               "'sudo chown root:<shadow-group> <file> && sudo "
                               "chmod 0640 <file>' (Debian group: shadow)."))
        elif mode & ~max_mode:
            out.append(Finding("HS-006", _acct_fn.check_name, CATEGORY,
                               "VULNERABLE", "MEDIUM", 5.5, loc,
                               "permissions %s are broader than recommended %s"
                               % (mode_str(st), format(max_mode, "04o")),
                               "The file is readable/writable by more principals "
                               "than required, increasing exposure of account data.",
                               "Tighten: 'sudo chmod %s <file>'."
                               % format(max_mode, "04o")))
        else:
            oks.append(loc)
    if not out:
        return [secure_finding(_acct_fn, "; ".join(oks),
                               "verified " + "; ".join(oks),
                               "All account database files have safe ownership and "
                               "permissions.")]
    return out


_acct_fn = None


# ---------------------------------------------------------------- HS-007..HS-013 (sysctl)
def _sysctl_check(ctx, fn, items, severity, score, what, why, fix):
    bad, missing = [], []
    for key, okvals in items:
        val = read_sysctl(ctx, key)
        if val is None:
            missing.append(key)
            continue
        if val not in okvals:
            bad.append("%s = %s   (expected %s)" % (key, val, " or ".join(okvals)))
    if bad:
        ev, _ = cap_lines(bad, 10)
        return [Finding(fn.check_id, fn.check_name, CATEGORY, "VULNERABLE",
                        severity, score, "/proc/sys (" + ", ".join(k for k, _ in items) + ")",
                        ev,
                        why + (" Parameters not readable in this environment: %s."
                               % ", ".join(missing) if missing else ""),
                        fix)]
    note = "All checked parameters are set to hardened values: " + \
        "; ".join("%s=%s" % (k, read_sysctl(ctx, k) or "?") for k, _ in items) + "."
    return [secure_finding(fn, "/proc/sys", note,
                           what + " verified to be in the hardened state.")]


@register("HS-007", "Kernel: IPv4/IPv6 packet forwarding enabled", CATEGORY)
def check_ip_forward(ctx):
    return _sysctl_check(
        ctx, _ipf_fn,
        [("net.ipv4.ip_forward", ("0",)), ("net.ipv6.conf.all.forwarding", ("0",))],
        "MEDIUM", 5.0,
        "Packet forwarding",
        "Host-level IP forwarding turns the machine into a router. On single-purpose "
        "servers it widens the network attack surface (packet relaying, spoofing, "
        "bypassing network segmentation) and is commonly required only for gateways, "
        "routers and container hosts.",
        "Disable unless the host is a router/container host: add "
        "'net.ipv4.ip_forward = 0' and 'net.ipv6.conf.all.forwarding = 0' to "
        "/etc/sysctl.d/99-hardening.conf, then run 'sudo sysctl --system'.")


_ipf_fn = None


@register("HS-008", "Kernel: ICMP redirects accepted/sent", CATEGORY)
def check_icmp_redirects(ctx):
    return _sysctl_check(
        ctx, _icmp_fn,
        [("net.ipv4.conf.all.accept_redirects", ("0",)),
         ("net.ipv4.conf.default.accept_redirects", ("0",)),
         ("net.ipv4.conf.all.send_redirects", ("0",)),
         ("net.ipv6.conf.all.accept_redirects", ("0",))],
        "MEDIUM", 5.2,
        "ICMP redirect hardening",
        "ICMP redirects can be spoofed by an on-path attacker to alter the host's "
        "routing table, enabling man-in-the-middle and traffic-redirection attacks. "
        "Hardened hosts ignore and never send them.",
        "Set accept_redirects/send_redirects to 0 (all and default, IPv4+IPv6) in "
        "/etc/sysctl.d/99-hardening.conf and apply with 'sudo sysctl --system'.")


_icmp_fn = None


@register("HS-009", "Kernel: SYN flood protection (tcp_syncookies)", CATEGORY)
def check_syncookies(ctx):
    return _sysctl_check(
        ctx, _syn_fn,
        [("net.ipv4.tcp_syncookies", ("1",))],
        "MEDIUM", 5.3,
        "SYN-cookies",
        "With syncookies disabled, a TCP SYN flood can exhaust the backlog queue and "
        "deny service to legitimate clients.",
        "Set 'net.ipv4.tcp_syncookies = 1' in /etc/sysctl.d/99-hardening.conf and "
        "apply with 'sudo sysctl --system'.")


_syn_fn = None


@register("HS-010", "Kernel: source-routed packets accepted", CATEGORY)
def check_source_route(ctx):
    return _sysctl_check(
        ctx, _sr_fn,
        [("net.ipv4.conf.all.accept_source_route", ("0",)),
         ("net.ipv4.conf.default.accept_source_route", ("0",)),
         ("net.ipv6.conf.all.accept_source_route", ("0",))],
        "MEDIUM", 5.2,
        "Source-route hardening",
        "Source-routed packets specify their own path through the network and are "
        "almost never legitimately needed; they facilitate spoofing and "
        "routing-table manipulation.",
        "Set accept_source_route to 0 (all and default, IPv4+IPv6) in "
        "/etc/sysctl.d/99-hardening.conf and apply with 'sudo sysctl --system'.")


_sr_fn = None


@register("HS-011", "Kernel: pointer/dmesg information leak restriction", CATEGORY)
def check_kptr(ctx):
    return _sysctl_check(
        ctx, _kptr_fn,
        [("kernel.kptr_restrict", ("1", "2")), ("kernel.dmesg_restrict", ("1",))],
        "LOW", 2.8,
        "Kernel information-disclosure hardening",
        "Unrestricted kernel pointers (/proc/kallsyms etc.) and open dmesg make "
        "kernel exploitation significantly easier by leaking kernel addresses and "
        "sensitive log data to unprivileged users.",
        "Set 'kernel.kptr_restrict = 1' (or 2) and 'kernel.dmesg_restrict = 1' in "
        "/etc/sysctl.d/99-hardening.conf and apply with 'sudo sysctl --system'.")


_kptr_fn = None


@register("HS-012", "Kernel: ASLR (address space randomisation)", CATEGORY)
def check_aslr(ctx):
    return _sysctl_check(
        ctx, _aslr_fn,
        [("kernel.randomize_va_space", ("2",))],
        "MEDIUM", 6.1,
        "ASLR",
        "Address Space Layout Randomisation (full, value 2) randomises stack, heap "
        "and library addresses. With ASLR off or partial, memory-corruption "
        "exploits become far more reliable.",
        "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d/99-hardening.conf "
        "and apply with 'sudo sysctl --system'.")


_aslr_fn = None


@register("HS-013", "Kernel: SUID core dumps", CATEGORY)
def check_suid_dumpable(ctx):
    return _sysctl_check(
        ctx, _dump_fn,
        [("fs.suid_dumpable", ("0",))],
        "LOW", 3.3,
        "Core-dump hardening",
        "If SUID programs may dump core (fs.suid_dumpable != 0), crash dumps of "
        "privileged processes can contain passwords, keys and other secrets "
        "readable by unprivileged users.",
        "Set 'fs.suid_dumpable = 0' in /etc/sysctl.d/99-hardening.conf and apply "
        "with 'sudo sysctl --system'. Also add '* hard core 0' to "
        "/etc/security/limits.conf.")


_dump_fn = None


# ---------------------------------------------------------------- HS-014
@register("HS-014", "Password hashing scheme strength", CATEGORY)
def check_hash_scheme(ctx):
    kv = parse_kv_file("/etc/login.defs")
    if kv is None:
        return [skipped_finding(_hash_fn, "/etc/login.defs",
                                "/etc/login.defs is not readable in this environment.")]
    method = kv.get("ENCRYPT_METHOD", "").upper()
    if method in ("SHA512", "YESCRYPT"):
        return [secure_finding(_hash_fn, "/etc/login.defs",
                               "ENCRYPT_METHOD %s" % (method or "unset"),
                               "New passwords are hashed with %s, a modern salted "
                               "and (for yescrypt) memory-hard scheme." % method)]
    sev = "MEDIUM"
    return [Finding("HS-014", _hash_fn.check_name, CATEGORY, "VULNERABLE", sev, 6.4,
                    "/etc/login.defs:ENCRYPT_METHOD",
                    "ENCRYPT_METHOD = %s (or unset)" % (method or "(unset)"),
                    "Weak or unspecified password hashing allows fast offline "
                    "cracking of any hash that leaks (see HS-006). DES/MD5 hashes "
                    "fall to GPU brute-force in seconds to hours.",
                    "In /etc/login.defs set 'ENCRYPT_METHOD SHA512' (or YESCRYPT on "
                    "Debian 12+) and require all users to change passwords so hashes "
                    "are regenerated: 'sudo chage -d 0 <user>'.")]


_hash_fn = None


# ---------------------------------------------------------------- HS-015
@register("HS-015", "World-writable tmp dirs mount hardening (noexec/nosuid/nodev)", CATEGORY)
def check_tmp_mount(ctx):
    data = ctx.cat("/proc/mounts") or ""
    mounts = {}
    for line in data.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            mounts.setdefault(parts[1], parts[3])
    targets = ["/tmp", "/var/tmp", "/dev/shm"]
    out, oks = [], []
    for t in targets:
        if t not in mounts:
            oks.append("%s : not a separate mount (root filesystem)" % t)
            continue
        opts = mounts[t]
        missing = [o for o in ("nodev", "nosuid", "noexec") if o not in opts.split(",")]
        if missing:
            out.append(Finding("HS-015", _tmp_fn.check_name, CATEGORY, "VULNERABLE",
                               "MEDIUM", 4.9, t,
                               "mounted with options '%s'; missing %s" % (opts, ", ".join(missing)),
                               "Tmp-style filesystems without nodev/nosuid/noexec let "
                               "attackers execute binaries or abuse device nodes from "
                               "world-writable scratch space - a standard step in "
                               "post-exploitation chains.",
                               "Add '%s %s nodev,nosuid,noexec' to /etc/fstab for %s, "
                               "or remount live with 'sudo mount -o remount,"
                               "nodev,nosuid,noexec %s'. Note: noexec on /dev/shm can "
                               "break Chromium-based browsers." % (t, t, t, t)))
        else:
            oks.append("%s : %s (all hardening flags present)" % (t, opts))
    if not out:
        return [info_finding(_tmp_fn, "; ".join(oks),
                             "\n".join(oks),
                             "No dedicated tmp mounts found; they share the root "
                             "filesystem. If this host is a physical/virtual server "
                             "(not a container), CIS recommends separate /tmp, "
                             "/var/tmp and /dev/shm partitions with nodev,nosuid,"
                             "noexec options.",
                             "Consider a dedicated /tmp partition or tmpfs entry in "
                             "/etc/fstab: 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0'.")]
    return out


_tmp_fn = None


# module-level function references used above
def _bind_self():
    global _suid_fn, _self_fn, _wwf_fn, _wwd_fn, _uno_fn, _acct_fn, _ipf_fn, _icmp_fn
    global _syn_fn, _sr_fn, _kptr_fn, _aslr_fn, _dump_fn, _hash_fn, _tmp_fn
    FN = check_suid_inventory
    _self_fn = check_ww_suid
    _suid_fn = check_suid_inventory
    _wwf_fn = check_world_writable_files
    _wwd_fn = check_world_writable_dirs
    _uno_fn = check_unowned_files
    _acct_fn = check_account_file_perms
    _ipf_fn = check_ip_forward
    _icmp_fn = check_icmp_redirects
    _syn_fn = check_syncookies
    _sr_fn = check_source_route
    _kptr_fn = check_kptr
    _aslr_fn = check_aslr
    _dump_fn = check_suid_dumpable
    _hash_fn = check_hash_scheme
    _tmp_fn = check_tmp_mount


_bind_self()

CHECKS = [check_suid_inventory, check_ww_suid, check_world_writable_files,
          check_world_writable_dirs, check_unowned_files, check_account_file_perms,
          check_ip_forward, check_icmp_redirects, check_syncookies,
          check_source_route, check_kptr, check_aslr, check_suid_dumpable,
          check_hash_scheme, check_tmp_mount]
