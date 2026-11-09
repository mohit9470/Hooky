#!/usr/bin/env python3
"""Hooky - Users, Authentication & Privileges audit module (AU-xxx)."""

import os
import re
from .core import (register, Finding, secure_finding, skipped_finding,
                   info_finding, parse_colon_file, read_file, read_sysctl,
                   mode_str, is_world_readable, is_group_readable,
                   is_world_writable, is_group_writable, owner_names, cap_lines)

CATEGORY = "Users & Authentication"

VALID_SYSTEM_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                       "/usr/bin/false", "/bin/sync", "/sbin/shutdown",
                       "/sbin/halt", "/usr/sbin/nologin-mount")


# ---------------------------------------------------------------- AU-001
@register("AU-001", "Non-root accounts with UID 0", CATEGORY)
def check_uid0(ctx):
    rows = parse_colon_file("/etc/passwd")
    if rows is None:
        return [skipped_finding(_uid0_fn, "/etc/passwd", "/etc/passwd not readable.")]
    bad = []
    for i, f in enumerate(rows):
        if len(f) < 7:
            continue
        user, uid = f[0], f[2]
        if uid.isdigit() and int(uid) == 0 and user != "root":
            bad.append("line %d: account '%s' has UID 0" % (i + 1, user))
    if bad:
        return [Finding("AU-001", _uid0_fn.check_name, CATEGORY, "VULNERABLE",
                        "CRITICAL", 9.7, "/etc/passwd:" + ",".join(b.split(":")[1].split()[1] for b in bad),
                        "\n".join(bad),
                        "Every account with UID 0 has unrestricted root power. "
                        "Duplicate UID-0 accounts defeat per-account auditing, "
                        "sudo controls and are a common backdoor technique.",
                        "Investigate the account origin immediately. Disable it "
                        "('sudo usermod -L <user> && sudo usermod -s /usr/sbin/nologin "
                        "<user>') or change its UID ('sudo usermod -u <newuid> <user>') "
                        "unless it is a documented administrative requirement.")]
    return [secure_finding(_uid0_fn, "/etc/passwd", "only 'root' has UID 0",
                           "No hidden UID-0 backdoor accounts found.")]


_uid0_fn = None


# ---------------------------------------------------------------- AU-002
@register("AU-002", "Accounts with an empty password hash", CATEGORY)
def check_empty_passwords(ctx):
    rows = parse_colon_file("/etc/shadow")
    if rows is None:
        return [skipped_finding(_empty_fn, "/etc/shadow",
                                "/etc/shadow is only readable by root (or the "
                                "'shadow' group). Re-run the audit as root to "
                                "execute this test.")]
    bad = []
    for i, f in enumerate(rows):
        if len(f) < 2:
            continue
        user, pw = f[0], f[1]
        if pw == "":
            bad.append("line %d: account '%s' has an EMPTY password hash" % (i + 1, user))
    if bad:
        return [Finding("AU-002", _empty_fn.check_name, CATEGORY, "VULNERABLE",
                        "CRITICAL", 9.9, "/etc/shadow",
                        "\n".join(bad),
                        "An empty password field allows the account to log in with "
                        "no password at all (depending on PAM limits, even over "
                        "SSH when PermitEmptyPasswords is enabled). This is a "
                        "direct, authentication-free path into the system.",
                        "Lock the account ('sudo passwd -l <user>') and set a strong "
                        "password or disable it entirely ('sudo usermod -s "
                        "/usr/sbin/nologin <user>').")]
    return [secure_finding(_empty_fn, "/etc/shadow",
                           "%d shadow entries checked; no empty password hashes"
                           % len(rows),
                           "All password hashes are set, locked ('!'/'*') or "
                           "otherwise non-empty.")]


_empty_fn = None


# ---------------------------------------------------------------- AU-003
@register("AU-003", "Password aging policy (login.defs)", CATEGORY)
def check_password_aging(ctx):
    kv = {}
    data = read_file("/etc/login.defs")
    if data is None:
        return [skipped_finding(_aging_fn, "/etc/login.defs",
                                "/etc/login.defs not readable.")]
    for line in data.splitlines():
        m = re.match(r"^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN)\s+(\d+)",
                     line.strip())
        if m:
            kv.setdefault(m.group(1), m.group(2))
    out = []
    mx = kv.get("PASS_MAX_DAYS")
    if mx is None or int(mx) > 90:
        out.append(Finding("AU-003", _aging_fn.check_name, CATEGORY, "VULNERABLE",
                           "MEDIUM", 5.0, "/etc/login.defs:PASS_MAX_DAYS",
                           "PASS_MAX_DAYS = %s (CIS recommends <= 90)" % (mx or "(unset, default 99999)"),
                           "Without a maximum password age, credentials compromised "
                           "once remain valid indefinitely, extending the window of "
                           "an undetected breach.",
                           "Set 'PASS_MAX_DAYS 90' in /etc/login.defs and apply to "
                           "existing accounts: 'sudo chage --maxdays 90 <user>'."))
    mn = kv.get("PASS_MIN_DAYS")
    if mn is not None and int(mn) < 1:
        out.append(Finding("AU-003", _aging_fn.check_name, CATEGORY, "VULNERABLE",
                           "LOW", 2.6, "/etc/login.defs:PASS_MIN_DAYS",
                           "PASS_MIN_DAYS = %s (recommend >= 1)" % mn,
                           "Allowing immediate password changes lets users cycle "
                           "through passwords to defeat reuse history rules.",
                           "Set 'PASS_MIN_DAYS 1' (or higher per policy)."))
    wa = kv.get("PASS_WARN_AGE")
    if wa is None or int(wa) < 7:
        out.append(Finding("AU-003", _aging_fn.check_name, CATEGORY, "VULNERABLE",
                           "LOW", 2.4, "/etc/login.defs:PASS_WARN_AGE",
                           "PASS_WARN_AGE = %s (recommend >= 7)" % (wa or "(unset, default 7)"),
                           "Users should receive advance warning before their "
                           "password expires to avoid lockouts and sticky-note "
                           "workarounds.",
                           "Set 'PASS_WARN_AGE 7' in /etc/login.defs."))
    if not out:
        return [secure_finding(_aging_fn, "/etc/login.defs",
                               "PASS_MAX_DAYS=%s PASS_MIN_DAYS=%s PASS_WARN_AGE=%s"
                               % (kv.get("PASS_MAX_DAYS"), kv.get("PASS_MIN_DAYS"),
                                  kv.get("PASS_WARN_AGE")),
                               "Password aging policy meets CIS baseline thresholds.")]
    return out


_aging_fn = None


# ---------------------------------------------------------------- AU-004
@register("AU-004", "Password complexity policy (pam_pwquality)", CATEGORY)
def check_pwquality(ctx):
    conf = read_file("/etc/security/pwquality.conf")
    pam_paths = ("/etc/pam.d/common-password", "/etc/pam.d/system-auth",
                 "/etc/pam.d/passwd")
    pam_data = None
    for p in pam_paths:
        d = read_file(p)
        if d and ("pwquality" in d or "cracklib" in d):
            pam_data = (p, d)
            break
    if conf is None and pam_data is None:
        return [Finding("AU-004", _pwq_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 5.3, "/etc/security/pwquality.conf (absent)",
                        "No pwquality/cracklib configuration or PAM integration found.",
                        "Without a complexity policy users can set trivially "
                        "guessable passwords ('password123'), which credential-"
                        "stuffing and brute-force attacks exploit within minutes.",
                        "Install and enable the policy: 'sudo apt-get install "
                        "libpam-pwquality' (Debian/Ubuntu), then set in "
                        "/etc/security/pwquality.conf at minimum: minlen = 12, "
                        "minclass = 3 (or dcredit/ucredit/lcredit/ocredit = -1).")]
    minlen = None
    minclass = None
    if conf:
        for line in conf.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            m = re.match(r"minlen\s*=\s*(\d+)", line)
            if m:
                minlen = int(m.group(1))
            m = re.match(r"minclass\s*=\s*(\d+)", line)
            if m:
                minclass = int(m.group(1))
    out = []
    loc = "/etc/security/pwquality.conf"
    if minlen is None:
        out.append(Finding("AU-004", _pwq_fn.check_name, CATEGORY, "VULNERABLE",
                           "MEDIUM", 5.3, loc + ":minlen",
                           "minlen is not set (default 8, CIS recommends >= 14)",
                           "Short passwords fall to offline and online brute-force "
                           "attacks; length is the dominant factor in password "
                           "strength.",
                           "Set 'minlen = 14' (12 acceptable) in "
                           "/etc/security/pwquality.conf."))
    elif minlen < 8:
        out.append(Finding("AU-004", _pwq_fn.check_name, CATEGORY, "VULNERABLE",
                           "MEDIUM", 5.3, loc + ":minlen",
                           "minlen = %d (below the 8-character minimum)" % minlen,
                           "Passwords shorter than 8 characters are trivially "
                           "crackable offline.",
                           "Raise minlen to at least 12 (14 recommended)."))
    elif minlen < 12:
        out.append(Finding("AU-004", _pwq_fn.check_name, CATEGORY, "VULNERABLE",
                           "LOW", 3.0, loc + ":minlen",
                           "minlen = %d (8-11; CIS hardening recommends >= 14)" % minlen,
                           "The minimum length is acceptable but below CIS "
                           "hardening guidance.",
                           "Consider raising minlen to 14."))
    if minclass is None and minlen is not None:
        has_classes = any(k in (conf or "") for k in ("dcredit", "ucredit", "lcredit", "ocredit"))
        if not has_classes:
            out.append(Finding("AU-004", _pwq_fn.check_name, CATEGORY, "VULNERABLE",
                               "MEDIUM", 4.7, loc,
                               "neither minclass nor per-class credits are configured",
                               "Without character-class requirements users may pick "
                               "single-alphabet passwords, easing dictionary attacks.",
                               "Set 'minclass = 3' (or all four credit lines) in "
                               "pwquality.conf."))
    if not out:
        return [secure_finding(_pwq_fn, loc,
                               "minlen=%s minclass=%s" % (minlen, minclass),
                               "Password complexity policy meets the baseline.")]
    return out


_pwq_fn = None


# ---------------------------------------------------------------- AU-005
@register("AU-005", "Failed-login lockout (pam_faillock)", CATEGORY)
def check_faillock(ctx):
    found = None
    for p in ("/etc/pam.d/common-auth", "/etc/pam.d/system-auth",
              "/etc/pam.d/password-auth"):
        d = read_file(p)
        if d is None:
            continue
        if "pam_faillock" in d or "pam_tally2" in d:
            found = p
            break
    if found:
        return [secure_finding(_fail_fn, found,
                               "pam_faillock/pam_tally2 present",
                               "Repeated failed logins lock the account, slowing "
                               "online password guessing to a crawl.")]
    return [Finding("AU-005", _fail_fn.check_name, CATEGORY, "VULNERABLE",
                    "MEDIUM", 5.8, "/etc/pam.d/* (common-auth / system-auth)",
                    "No pam_faillock (or pam_tally2) rule found in PAM configuration.",
                    "Without account lockout, attackers can brute-force passwords "
                    "online indefinitely; SSH/HTTP logs show thousands of attempts "
                    "routinely on internet-facing hosts.",
                    "Enable faillock (Debian 12+/RHEL): add to "
                    "/etc/pam.d/common-auth: 'auth required pam_faillock.so "
                    "preauth deny=5 unlock_time=900' and 'auth required "
                    "pam_faillock.so authfail deny=5 unlock_time=900', or run "
                    "'sudo authselect enable-feature with-faillock' on RHEL-family.")]


_fail_fn = None


# ---------------------------------------------------------------- AU-006
@register("AU-006", "Passwordless sudo / NOPASSWD grants", CATEGORY)
def check_sudo_nopasswd(ctx):
    files = ["/etc/sudoers"]
    try:
        if os.path.isdir("/etc/sudoers.d"):
            for n in sorted(os.listdir("/etc/sudoers.d")):
                if n.endswith((".save", ".dpkg-dist", "~")) or n.startswith("."):
                    continue
                files.append("/etc/sudoers.d/" + n)
    except OSError:
        pass
    lines_all = []
    readable = False
    for p in files:
        data = read_file(p)
        if data is None:
            continue
        readable = True
        for i, line in enumerate(data.splitlines()):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "NOPASSWD" in s or "!authenticate" in s or "Defaults !authenticate" in s:
                lines_all.append("%s:%d: %s" % (p, i + 1, s))
    if not readable:
        return [skipped_finding(_sudo_fn, "/etc/sudoers",
                                "sudoers configuration is only readable by root. "
                                "Re-run the audit as root to execute this test.")]
    if lines_all:
        ev, total = cap_lines(lines_all, 12)
        return [Finding("AU-006", _sudo_fn.check_name, CATEGORY, "VULNERABLE",
                        "HIGH", 7.7, "; ".join(sorted({l.split(':')[0] + ':' + l.split(':')[1]
                                                       for l in lines_all})),
                        "%d passwordless-sudo grants:\n%s" % (total, ev),
                        "NOPASSWD sudo entries let the mapped user execute commands "
                        "as root without re-authenticating. Anyone who steals that "
                        "user's session (unlocked desktop, compromised agent, "
                        "malware) gets instant root; it also weakens accountability.",
                        "Restrict NOPASSWD to single, absolutely-required commands "
                        "with argument lists (e.g. '%backup ALL=(root) NOPASSWD: "
                        "/usr/bin/rsync') instead of ALL. Remove blanket "
                        "'NOPASSWD: ALL' grants, and never add '!authenticate'.")]
    return [secure_finding(_sudo_fn, "/etc/sudoers, /etc/sudoers.d/*",
                           "no NOPASSWD / !authenticate grants found",
                           "Every privileged action requires re-authentication.")]


_sudo_fn = None


# ---------------------------------------------------------------- AU-007
@register("AU-007", "System accounts with an interactive login shell", CATEGORY)
def check_system_shells(ctx):
    rows = parse_colon_file("/etc/passwd")
    if rows is None:
        return [skipped_finding(_shell_fn, "/etc/passwd", "/etc/passwd not readable.")]
    bad = []
    for i, f in enumerate(rows):
        if len(f) < 7:
            continue
        user, uid, shell = f[0], f[2], f[6]
        if not uid.isdigit():
            continue
        uidn = int(uid)
        if uidn == 0 or uidn >= 1000:
            continue
        if user in ("sync", "shutdown", "halt"):
            continue
        if shell not in VALID_SYSTEM_SHELLS:
            bad.append("line %d: system account '%s' (uid %s) uses shell %s"
                       % (i + 1, user, uid, shell))
    if bad:
        ev, total = cap_lines(bad, 10)
        return [Finding("AU-007", _shell_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 4.4, "/etc/passwd",
                        "%d system accounts with interactive shells:\n%s" % (total, ev),
                        "Daemon/service accounts should never log in interactively. "
                        "A shell on a service account is a stable foothold for an "
                        "attacker (service accounts usually have no password expiry "
                        "and no human watching them).",
                        "Set a nologin shell: 'sudo usermod -s /usr/sbin/nologin "
                        "<account>' for each listed account after confirming the "
                        "service does not require shell login.")]
    return [secure_finding(_shell_fn, "/etc/passwd",
                           "all uid<1000 system accounts use nologin/false/sync-type shells",
                           "System accounts cannot be used for interactive login.")]


_shell_fn = None


# ---------------------------------------------------------------- AU-008
@register("AU-008", "Duplicate UIDs / GIDs", CATEGORY)
def check_duplicate_ids(ctx):
    rows = parse_colon_file("/etc/passwd")
    if rows is None:
        return [skipped_finding(_dup_fn, "/etc/passwd", "/etc/passwd not readable.")]
    seen, dups = {}, []
    for f in rows:
        if len(f) < 3 or not f[2].isdigit():
            continue
        seen.setdefault(f[2], []).append(f[0])
    for uid, users in seen.items():
        if len(users) > 1 and uid != "65534":
            dups.append("UID %s shared by: %s" % (uid, ", ".join(users)))
    grows = parse_colon_file("/etc/group") or []
    gseen = {}
    for f in grows:
        if len(f) < 3 or not f[2].isdigit():
            continue
        gseen.setdefault(f[2], []).append(f[0])
    for gid, groups in gseen.items():
        if len(groups) > 1 and gid != "65534":
            dups.append("GID %s shared by: %s" % (gid, ", ".join(groups)))
    if dups:
        ev, _ = cap_lines(dups, 10)
        return [Finding("AU-008", _dup_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 4.2, "/etc/passwd, /etc/group", ev,
                        "Duplicate IDs cause audit-log ambiguity and unintended "
                        "permission sharing; attackers exploit duplicate UIDs to "
                        "masquerade as other accounts.",
                        "Give each account/group a unique ID ('sudo usermod -u "
                        "<uid> <user>' / 'groupmod -g') or remove the redundant "
                        "account.")]
    return [secure_finding(_dup_fn, "/etc/passwd, /etc/group",
                           "no duplicate UIDs/GIDs (excluding 'nobody' 65534)",
                           "Every account and group has a unique numeric ID.")]


_dup_fn = None


# ---------------------------------------------------------------- AU-009
@register("AU-009", "PATH hygiene for privileged users", CATEGORY)
def check_path_hygiene(ctx):
    paths = []
    if ctx.is_root:
        paths.append(("runtime PATH (root)", os.environ.get("PATH", "")))
    for p, label in (("/etc/profile", "/etc/profile:PATH"),
                     ("/root/.profile", "/root/.profile:PATH"),
                     ("/root/.bashrc", "/root/.bashrc:PATH")):
        d = read_file(p)
        if d:
            for i, line in enumerate(d.splitlines()):
                m = re.match(r"\s*(?:export\s+)?PATH\s*=\s*[\"']?([^\"'\n]+)", line)
                if m and ":" in m.group(1):
                    paths.append(("%s line %d" % (p, i + 1), m.group(1)))
                    break
    if not paths:
        return [skipped_finding(_path_fn, "PATH",
                                "Privileged PATH configuration is not readable "
                                "without root. Re-run as root for this test.")]
    issues = []
    for src, pval in paths:
        for entry in pval.split(":"):
            if entry == "" or entry == ".":
                issues.append("%s: empty element or '.' in PATH ('%s')" % (src, pval))
            elif entry.startswith("$"):
                continue
            else:
                st = ctx.stat(entry)
                if st and is_world_writable(st):
                    issues.append("%s: PATH element '%s' is world-writable (mode %s)"
                                  % (src, entry, mode_str(st)))
    if issues:
        ev, _ = cap_lines(issues, 8)
        return [Finding("AU-009", _path_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 5.6, "; ".join(i.split(":")[0] for i in issues[:3]), ev,
                        "A relative ('.'), empty or world-writable PATH element lets "
                        "an attacker plant a trojan binary (e.g. fake 'ls' or "
                        "'sudo') that a privileged user executes unknowingly.",
                        "Remove '.' and empty elements from root's PATH and tighten "
                        "directory permissions ('sudo chmod o-w <dir>'). Root's PATH "
                        "should never contain writable-by-others directories.")]
    return [secure_finding(_path_fn, "PATH configuration",
                           "root PATH entries audited: no '.', empty or "
                           "world-writable elements",
                           "Privileged PATH is safe against binary-planting.")]


_path_fn = None


# ---------------------------------------------------------------- AU-010
@register("AU-010", "Legacy trust files (.rhosts / hosts.equiv / .shosts)", CATEGORY)
def check_trust_files(ctx):
    hits = []
    for p in ("/etc/hosts.equiv", "/etc/shosts.equiv", "/root/.rhosts",
              "/root/.shosts"):
        if os.path.exists(p):
            hits.append(p)
    home_roots = []
    for base in ("/home", "/root"):
        try:
            home_roots += [os.path.join(base, n) for n in os.listdir(base)]
        except OSError:
            pass
    for h in home_roots:
        for name in (".rhosts", ".shosts", ".netrc"):
            p = os.path.join(h, name)
            if os.path.exists(p):
                hits.append(p)
    if hits:
        ev = "\n".join(hits[:12])
        return [Finding("AU-010", _trust_fn.check_name, CATEGORY, "VULNERABLE",
                        "HIGH", 7.9, hits[0],
                        "%d legacy trust/credential files present:\n%s" % (len(hits), ev),
                        "hosts.equiv/.rhosts/.shosts grant passwordless trust between "
                        "hosts (r-protocols and legacy SSH options) and .netrc stores "
                        "cleartext credentials. These files silently bypass "
                        "authentication controls.",
                        "Delete the files ('sudo rm <file>') and ensure "
                        "'IgnoreRhosts yes' is set in sshd_config. Migrate any "
                        ".netrc credentials into a proper secrets manager.")]
    return [secure_finding(_trust_fn, "/etc, /root, /home/*",
                           "no hosts.equiv / .rhosts / .shosts / .netrc files found",
                           "No legacy host-trust or cleartext-credential files.")]


_trust_fn = None


# ---------------------------------------------------------------- AU-011
@register("AU-011", "root SSH authorized_keys & permissions", CATEGORY)
def check_root_authorized_keys(ctx):
    p = "/root/.ssh/authorized_keys"
    if not os.path.exists(p):
        return [secure_finding(_ak_fn, p, "file not present",
                               "No root SSH authorized_keys file; root cannot be "
                               "reached with injected public keys.")]
    st = ctx.stat(p)
    if st is None:
        return [skipped_finding(_ak_fn, p, "file exists but is not readable "
                                           "without root.")]
    out = []
    data = read_file(p) or ""
    keys = [ln for ln in data.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if is_world_readable(st) or is_group_readable(st) or is_world_writable(st) or is_group_writable(st):
        out.append(Finding("AU-011", _ak_fn.check_name, CATEGORY, "VULNERABLE",
                           "HIGH", 7.4, "%s (mode %s, owner %s)" % (p, mode_str(st), owner_names(st)),
                           "authorized_keys with over-permissive mode %s; %d key(s) loaded"
                           % (mode_str(st), len(keys)),
                           "A writable authorized_keys allows any user who can write "
                           "it to inject their own public key and obtain root access "
                           "via SSH.",
                           "Harden: 'sudo chmod 600 %s && sudo chown root:root %s' "
                           "and review the listed keys are authorised." % (p, p)))
    else:
        out.append(info_finding(_ak_fn, p,
                                "mode %s (safe); %d authorized key(s): %s"
                                % (mode_str(st), len(keys),
                                   "; ".join((k.split()[0][:20] + "...") if k.split() else "?"
                                             for k in keys[:6]) or "none"),
                                "root authorized_keys exists with safe permissions. "
                                "Review the key inventory periodically; every key "
                                "listed is a root-login path.",
                                "Rotate or remove stale keys; prefer per-user "
                                "accounts + sudo over direct root SSH."))
    return out


_ak_fn = None


# ---------------------------------------------------------------- AU-012
@register("AU-012", "Interactive user account inventory", CATEGORY)
def check_user_inventory(ctx):
    rows = parse_colon_file("/etc/passwd")
    if rows is None:
        return [skipped_finding(_inv_fn, "/etc/passwd", "/etc/passwd not readable.")]
    users = []
    for f in rows:
        if len(f) < 7:
            continue
        uid = f[2]
        if uid.isdigit() and int(uid) >= 1000 and f[6] not in ("/bin/false",
                                                               "/usr/sbin/nologin",
                                                               "/sbin/nologin",
                                                               "/usr/bin/false"):
            users.append("uid %-6s %-16s shell=%s home=%s" % (uid, f[0], f[6], f[5]))
    lst, total = cap_lines(users, 20)
    return [info_finding(_inv_fn, "/etc/passwd",
                         "%d interactive-capable accounts:\n%s" % (total, lst),
                         "Informational inventory of accounts able to log in. "
                         "Confirm every entry maps to a real, current person or "
                         "service - orphaned accounts of former staff are a "
                         "leading insider-risk finding.",
                         "Disable departed users immediately: 'sudo usermod -L -s "
                         "/usr/sbin/nologin <user>' and remove after the retention "
                         "period.")]


_inv_fn = None


# module-level aliases used inside the check functions
_uid0_fn = check_uid0
_empty_fn = check_empty_passwords
_aging_fn = check_password_aging
_pwq_fn = check_pwquality
_fail_fn = check_faillock
_sudo_fn = check_sudo_nopasswd
_shell_fn = check_system_shells
_dup_fn = check_duplicate_ids
_path_fn = check_path_hygiene
_trust_fn = check_trust_files
_ak_fn = check_root_authorized_keys
_inv_fn = check_user_inventory

CHECKS = [check_uid0, check_empty_passwords, check_password_aging,
          check_pwquality, check_faillock, check_sudo_nopasswd,
          check_system_shells, check_duplicate_ids, check_path_hygiene,
          check_trust_files, check_root_authorized_keys, check_user_inventory]
