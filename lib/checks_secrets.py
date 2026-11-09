#!/usr/bin/env python3
"""Hooky - Secrets, Credentials & Config audit module (SC-xxx)."""

import os
import re
from .core import (register, Finding, secure_finding, skipped_finding,
                   info_finding, read_file, mode_str, is_world_readable,
                   is_group_readable, is_world_writable, is_group_writable,
                   owner_names, cap_lines, sanitize)

CATEGORY = "Secrets & Credentials"

SECRET_GREP_DIRS = ("/etc", "/opt", "/srv", "/var/www", "/home", "/root")
SECRET_GREP_DIRS_EXIST = tuple(d for d in SECRET_GREP_DIRS if os.path.isdir(d))

SECRET_PATTERNS = [
    r"(pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*\S+",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
]

FALSE_POSITIVE_RE = re.compile(
    r"^\s*#|"
    r"Authentication|use_authtok|pam_|minlen|minclass|dcredit|ucredit|lcredit|"
    r"ocredit|remember=|obscure|selinux| enforcing|shadow\s|passwd\s+required|"
    r"password\s+requisite|password\s+sufficient|password\s+\[|nologin|"
    r"\$\{\w+\}|\$\(.*\)|\{\{.*\}\}|<[^>]+>|TODO|CHANGEME|changeme|xxxx|"
    r"example\.com|@example|/usr/bin|/usr/sbin|_tty|PA_",
    re.IGNORECASE)

PLACEHOLDER_VALUES = re.compile(
    r"^['\"]?(\S{0,3}|placeholder|change-?me|my-?secret|password|secret|token|"
    r"key|value|xxxx+|\*+|\.+|<[^>]*>|\$\{[^}]*\}|%[^%]*%|none|true|false|null)\b",
    re.IGNORECASE)


def _clean_match(path, lineno, line):
    """Return cleaned evidence or None for false positives."""
    s = line.strip()
    if not s or FALSE_POSITIVE_RE.search(s):
        return None
    m = re.search(r"[=:]\s*(\S{1,120})", s)
    val = m.group(1) if m else ""
    if val and PLACEHOLDER_VALUES.match(val.strip("'\"")):
        return None
    return "%s:%d: %s" % (path, lineno, sanitize(s, 160, single_line=True))


# ---------------------------------------------------------------- SC-001
@register("SC-001", "SSH private keys with insecure file permissions", CATEGORY)
def check_ssh_key_perms(ctx):
    roots = []
    for base in ("/root", "/home"):
        try:
            roots += [os.path.join(base, n) for n in os.listdir(base)]
        except OSError:
            pass
    key_names = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity")
    out, checked = [], 0
    for home in roots:
        ssh = os.path.join(home, ".ssh")
        if not os.path.isdir(ssh):
            continue
        try:
            names = os.listdir(ssh)
        except OSError:
            continue
        for n in names:
            if n.endswith(".pub") or n in ("known_hosts", "authorized_keys",
                                           "config", "environment"):
                continue
            p = os.path.join(ssh, n)
            head = (read_file(p, 400) or "")
            if "PRIVATE KEY" not in head:
                continue
            checked += 1
            st = os.stat(p)
            if is_world_readable(st) or is_world_writable(st):
                out.append(Finding("SC-001", _sshk_fn.check_name, CATEGORY,
                                   "VULNERABLE", "CRITICAL", 9.3,
                                   "%s (mode %s, owner %s)" % (p, mode_str(st), owner_names(st)),
                                   "private key world-readable/writable",
                                   "Any local user can steal this private key and "
                                   "impersonate its owner on every host that trusts "
                                   "it. Keys with no passphrase are effectively "
                                   "permanent passwords.",
                                   "Restrict immediately: 'chmod 600 %s'. Assess "
                                   "exposure time, rotate the key pair, and add a "
                                   "passphrase." % p))
            elif is_group_readable(st) or is_group_writable(st):
                out.append(Finding("SC-001", _sshk_fn.check_name, CATEGORY,
                                   "VULNERABLE", "HIGH", 7.3,
                                   "%s (mode %s, owner %s)" % (p, mode_str(st), owner_names(st)),
                                   "private key group-readable/writable",
                                   "Every member of the file's group can steal this "
                                   "key and impersonate its owner.",
                                   "Restrict: 'chmod 600 %s' and rotate if exposure "
                                   "is suspected." % p))
    if out:
        return out
    if checked:
        return [secure_finding(_sshk_fn, "$HOME/.ssh (root + all users)",
                               "%d private key(s) checked; all have mode 0600-class "
                               "permissions" % checked,
                               "All SSH private keys are protected from other "
                               "users.")]
    return [info_finding(_sshk_fn, "$HOME/.ssh (root + all users)",
                         "no private SSH keys found in accessible home directories",
                         "No SSH client keys in readable locations. Keys may still "
                         "exist in root-readable areas - re-run as root for full "
                         "coverage.")]


_sshk_fn = None


# ---------------------------------------------------------------- SC-002
@register("SC-002", "Credentials typed into shell history files", CATEGORY)
def check_history_creds(ctx):
    homes = []
    for base in ("/root", "/home"):
        try:
            homes += [os.path.join(base, n) for n in os.listdir(base)]
        except OSError:
            pass
    out = []
    for home in homes:
        for name in (".bash_history", ".zsh_history", ".sh_history",
                     ".python_history", ".mysql_history", ".psql_history"):
            p = os.path.join(home, name)
            if not os.path.isfile(p):
                continue
            data = read_file(p, 1048576)
            if not data:
                continue
            hits = []
            for i, line in enumerate(data.splitlines()):
                if re.search(r"(?i)(pass(word|wd)?|pwd|api[_-]?key|token|secret)"
                             r"\s*[=:]\s*\S+|AKIA[0-9A-Z]{16}", line):
                    c = _clean_match(p, i + 1, line)
                    if c:
                        hits.append(c)
            if hits:
                ev, total = cap_lines(hits, 8)
                out.append(Finding("SC-002", _hist_fn.check_name, CATEGORY,
                                   "VULNERABLE", "MEDIUM", 5.9, p,
                                   "%d credential-looking entries:\n%s" % (total, ev),
                                   "Shell history files are plaintext and frequently "
                                   "copied into backups, dotfile repos and terminal "
                                   "sync services. Secrets typed on the command line "
                                   "are permanently exposed there (and via "
                                   "'history' to any process that can read the file).",
                                   "Purge the file: 'history -c && rm %s'; rotate the "
                                   "exposed credentials; preface future secrets with "
                                   "a leading space (HISTCONTROL=ignorespace) or use "
                                   "a secrets manager / environment injection." % p))
    if out:
        return out
    return [secure_finding(_hist_fn, "/root, /home/* (history files)",
                           "no credential-pattern entries found in readable "
                           "history files",
                           "Shell history files are free of typed secrets.")]


_hist_fn = None


# ---------------------------------------------------------------- SC-003
@register("SC-003", "World-readable key/credential files", CATEGORY)
def check_world_readable_creds(ctx):
    expr = ("-type f \\( -name '*.pem' -o -name '*.key' -o -name '*.p12' -o "
            "-name '*.pfx' -o -name '*.pgpass' -o -name '.netrc' -o -name "
            "'my.cnf' -o -name '_rsa' -o -name '.env' \\)")
    files = ctx.find(expr, max_results=800)
    out, checked = [], 0
    for p in files:
        st = ctx.stat(p)
        if st is None:
            continue
        head = (read_file(p, 512) or "")
        is_cred = ("PRIVATE KEY" in head or "ENCRYPTED PRIVATE" in head or
                   p.endswith((".pgpass", ".netrc", ".p12", ".pfx", ".key")) or
                   p.endswith(".env") or p.endswith("my.cnf"))
        if not is_cred:
            continue
        checked += 1
        if is_world_readable(st) or is_group_readable(st):
            sev = "HIGH" if "PRIVATE KEY" in head or p.endswith((".pgpass", ".netrc")) else "MEDIUM"
            out.append(Finding("SC-003", _wr_fn.check_name, CATEGORY, "VULNERABLE",
                               sev, 7.6 if sev == "HIGH" else 5.5,
                               "%s (mode %s, owner %s)" % (p, mode_str(st), owner_names(st)),
                               "credential file readable beyond its owner",
                               "This file contains cryptographic key or credential "
                               "material but is readable by other users/groups. Any "
                               "compromised service account can exfiltrate it.",
                               "Tighten: 'chmod 600 %s' and 'chown <service-user> "
                               "<file>'; move group access to a dedicated group." % p))
    if out:
        return out[:15]
    if checked:
        return [secure_finding(_wr_fn, "key/credential files (filesystem-wide)",
                               "%d credential file(s) checked; none are "
                               "group/world-readable" % checked,
                               "All credential files are owner-restricted.")]
    return [info_finding(_wr_fn, "key/credential files (filesystem-wide)",
                         "no credential-type files found in readable areas "
                         "(%d candidates scanned)" % len(files),
                         "No misplaced key material in accessible areas.")]


_wr_fn = None


# ---------------------------------------------------------------- SC-004
@register("SC-004", "Hardcoded secrets in configuration files", CATEGORY)
def check_hardcoded_secrets(ctx):
    if not SECRET_GREP_DIRS_EXIST:
        return [skipped_finding(_hc_fn, "/etc, /opt, /srv, /var/www, /home",
                                "None of the scanned configuration directories "
                                "exist in this environment.")]
    cmd = ["grep", "-rInEi"]
    for pat in SECRET_PATTERNS:
        cmd += ["-e", pat]
    for d in ("pam.d", "security", "ssl/certs", "ssl/private", "ca-certificates",
              "apt", "dpkg", "logcheck", "pki"):
        cmd += ["--exclude-dir", d]
    for g in ("*.pyc", "*.so", "*.so.*", "*.a", "*.o", "*.gz", "*.zip", "*.deb",
              "*.png", "*.jpg", "*.pdf", "shadow", "shadow-", "gshadow",
              "gshadow-", "*.pub", "*.log", "*.old", "*.bak"):
        cmd += ["--exclude", g]
    cmd += list(SECRET_GREP_DIRS_EXIST)
    rc, out, _ = ctx.run(cmd, timeout=90 if not ctx.quick else 25)
    matches = []
    if rc in (0, 1) and out:
        for line in out.splitlines()[:4000]:
            try:
                path, ln, content = line.split(":", 2)
            except ValueError:
                continue
            c = _clean_match(path, ln, content)
            if c:
                matches.append(c)
    # deduplicate
    seen, uniq = set(), []
    for m in matches:
        if m in seen:
            continue
        seen.add(m)
        uniq.append(m)
    if uniq:
        ev, total = cap_lines(uniq, 15)
        out = []
        for m in uniq[:12]:
            path = m.split(":")[0]
            lineno = m.split(":")[1]
            out.append(Finding("SC-004", _hc_fn.check_name, CATEGORY, "VULNERABLE",
                               "HIGH", 7.7, "%s:%s" % (path, lineno),
                               m.split(": ", 1)[-1],
                               "A configuration file contains what looks like an "
                               "embedded password, API key or private key. Anyone "
                               "who can read this file - including backup agents, "
                               "monitoring and every service account - inherits the "
                               "credential.",
                               "Move the secret to a secrets manager "
                               "(Vault/SOPS/docker secrets) or a root-only 0600 "
                               "environment file; rotate the exposed credential; "
                               "verify the file mode is 0600/0640."))
        if total > 12:
            out.append(Finding("SC-004", _hc_fn.check_name, CATEGORY, "VULNERABLE",
                               "HIGH", 7.7, uniq[12].split(":")[0],
                               "+ %d further credential-pattern matches:\n%s"
                               % (total - 12, "\n".join(uniq[12:30])) + ("\n..." if total > 30 else ""),
                               "Additional credential-looking lines were found.",
                               "Review every match; rotate and externalise each "
                               "secret found."))
        return out
    return [secure_finding(_hc_fn, ", ".join(SECRET_GREP_DIRS_EXIST),
                           "credential-pattern grep over %d directories returned no "
                           "plausible matches (false-positive filtered)"
                           % len(SECRET_GREP_DIRS_EXIST),
                           "No plaintext secrets detected in readable "
                           "configuration trees.")]


_hc_fn = None


# ---------------------------------------------------------------- SC-005
@register("SC-005", "Web application .env files exposed", CATEGORY)
def check_env_files(ctx):
    expr = "-type f -name '.env*'"
    roots = tuple(d for d in ("/var/www", "/srv", "/opt", "/home", "/root")
                  if os.path.isdir(d))
    if not roots:
        return [secure_finding(_env_fn, "web roots",
                               "no /var/www, /srv, /opt or home directories present",
                               "No web application roots to scan for .env files.")]
    files = ctx.find(expr, roots=roots, max_results=200)
    out = []
    for p in files:
        data = read_file(p, 32768) or ""
        juicy = []
        for i, line in enumerate(data.splitlines()):
            if re.match(r"^\s*[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|KEY|DSN)[A-Z0-9_]*\s*=",
                        line, re.IGNORECASE):
                c = _clean_match(p, i + 1, line)
                if c:
                    juicy.append(c)
        if juicy:
            ev, _t = cap_lines(juicy, 6)
            st = ctx.stat(p)
            perm = "(mode %s)" % mode_str(st) if st else ""
            out.append(Finding("SC-005", _env_fn.check_name, CATEGORY, "VULNERABLE",
                               "HIGH", 7.6, "%s %s" % (p, perm),
                               "%d secret-bearing entries:\n%s" % (len(juicy), ev),
                               "Application environment files carry database "
                               "passwords, API keys and signing secrets in "
                               "plaintext. When placed inside web roots they are "
                               "frequently retrievable over HTTP by mistake, and "
                               "any local reader inherits the application's full "
                               "credential set.",
                               "Move the file outside the web root or into a "
                               "secrets manager; set 'chmod 600'; ensure the web "
                               "server denies dotfiles "
                               "(nginx: 'location ~ /\\. { deny all; }'; Apache: "
                               "Require all denied for '.env')."))
    if out:
        return out
    return [secure_finding(_env_fn, "web roots " + ", ".join(roots),
                           "no .env files with credential entries found (%d "
                           "candidates)" % len(files),
                           "No exposed application environment files.")]


_env_fn = None


# ---------------------------------------------------------------- SC-006
@register("SC-006", "Docker daemon socket exposure", CATEGORY)
def check_docker_socket(ctx):
    p = "/var/run/docker.sock"
    st = ctx.stat(p)
    if st is None:
        return [secure_finding(_dk_fn, p, "socket not present",
                               "No Docker socket on this host (Docker not "
                               "installed or run elsewhere).")]
    import pwd as _pwd
    try:
        gname = _pwd.getgrgid(st.st_gid).gr_name
    except Exception:
        gname = str(st.st_gid)
    if is_world_writable(st) or is_world_readable(st):
        return [Finding("SC-006", _dk_fn.check_name, CATEGORY, "VULNERABLE",
                        "CRITICAL", 9.6, "%s (mode %s, owner %s:%s)"
                        % (p, mode_str(st), owner_names(st), gname),
                        "docker.sock is world-accessible (mode %s)" % mode_str(st),
                        "The Docker socket is an unrestricted root-equivalent API: "
                        "anyone with access can mount the host filesystem into a "
                        "container and become root instantly. World-accessible "
                        "docker.sock is a full host compromise waiting to happen.",
                        "Restore sane ownership: 'sudo chown root:docker %s && "
                        "sudo chmod 660 %s'; find out which process relaxed it. "
                        "Never expose the socket over TCP or to containers." % (p, p))]
    if gname == "docker" or (mode_str(st) in ("0660", "0664")):
        return [info_finding(_dk_fn, "%s (mode %s, owner %s:%s)"
                             % (p, mode_str(st), owner_names(st), gname),
                             "socket restricted to root/docker group",
                             "Standard configuration, but note: membership of the "
                             "'docker' group is de-facto root access. Audit who is "
                             "in that group ('getent group docker').",
                             "Keep group membership minimal; prefer rootless "
                             "Docker or podman where feasible.")]
    return [secure_finding(_dk_fn, p, "mode %s (owner %s:%s)"
                           % (mode_str(st), owner_names(st), gname),
                           "Docker socket is not exposed beyond its owner.")]


_dk_fn = None


# ---------------------------------------------------------------- SC-007
@register("SC-007", "Cron job security (permissions & embedded credentials)", CATEGORY)
def check_cron_files(ctx):
    paths = ["/etc/crontab"]
    for d in ("/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"):
        if os.path.isdir(d):
            try:
                paths += [os.path.join(d, n) for n in os.listdir(d)]
            except OSError:
                pass
    if len(paths) <= 1 and not os.path.exists("/etc/crontab"):
        return [secure_finding(_cron_fn, "/etc/crontab, /etc/cron.d, /var/spool/cron",
                               "no cron configuration files found",
                               "No cron jobs defined on this host.")]
    out, oks = [], []
    for p in paths:
        st = ctx.stat(p)
        if st is None:
            continue
        if is_world_writable(st) or is_group_writable(st):
            out.append(Finding("SC-007", _cron_fn.check_name, CATEGORY, "VULNERABLE",
                               "HIGH", 7.7, "%s (mode %s, owner %s)"
                               % (p, mode_str(st), owner_names(st)),
                               "cron file writable by non-root principals",
                               "Cron files are executed on schedule as their owner "
                               "(often root). A writable cron file is a guaranteed, "
                               "time-triggered privilege escalation.",
                               "Fix: 'sudo chown root:root %s && sudo chmod 600 %s' "
                               "(0600 root:root for /etc/crontab; spool files owned "
                               "by their user, 0600)." % (p, p)))
        else:
            data = read_file(p, 65536) or ""
            hits = []
            for i, line in enumerate(data.splitlines()):
                if re.search(r"(?i)(pass(word|wd)?|pwd|token|api[_-]?key)\s*[=:]\s*\S+",
                             line):
                    c = _clean_match(p, i + 1, line)
                    if c:
                        hits.append(c)
            if hits:
                out.append(Finding("SC-007", _cron_fn.check_name, CATEGORY,
                                   "VULNERABLE", "MEDIUM", 5.7, p,
                                   "credentials embedded in scheduled job:\n%s"
                                   % "\n".join(hits[:5]),
                                   "Scheduled jobs frequently embed passwords on "
                                   "their command line. Command lines are visible "
                                   "to every user via /proc and persist in logs.",
                                   "Externalise the credential into a 0600 config "
                                   "file or secrets store and rotate the exposed "
                                   "password."))
            else:
                oks.append("%s (mode %s)" % (p, mode_str(st)))
    if out:
        return out
    return [secure_finding(_cron_fn, "; ".join(oks[:4]) + ("..." if len(oks) > 4 else ""),
                           "%d cron files checked; safe modes, no embedded secrets"
                           % len(oks),
                           "Cron configuration is root-only and free of embedded "
                           "credentials.")]


_cron_fn = None


# ---------------------------------------------------------------- SC-008
@register("SC-008", "GRUB bootloader password protection", CATEGORY)
def check_grub_password(ctx):
    cfgs = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/etc/grub.d/40_custom",
            "/etc/grub.d/01_users"]
    found_cfg = False
    for p in cfgs:
        if os.path.exists(p):
            found_cfg = True
            data = read_file(p, 262144) or ""
            if "superusers" in data or "password_pbkdf2" in data or "password " in data.lower():
                return [secure_finding(_grub_fn, p,
                                       "GRUB superuser/password directive present",
                                       "Bootloader is protected against unattended "
                                       "kernel-parameter tampering (init=/bin/bash).")]
    if not found_cfg:
        return [skipped_finding(_grub_fn, "/boot/grub",
                                "No GRUB configuration found (container or "
                                "non-GRUB platform). Bootloader checks apply to "
                                "the physical/VM host instead.")]
    return [Finding("SC-008", _grub_fn.check_name, CATEGORY, "VULNERABLE",
                    "LOW", 3.4, "/boot/grub/grub.cfg",
                    "no 'set superusers=' or 'password_pbkdf2' directive found",
                    "Anyone with physical or console access can edit boot entries "
                    "and add init=/bin/bash to become root without credentials - "
                    "relevant for co-located servers, laptops and any host with "
                    "exposed console/KVM.",
                    "Set a GRUB password: 'grub-mkpasswd-pbkdf2', then create "
                    "/etc/grub.d/40_custom with 'set superusers=\"root\"' and "
                    "'password_pbkdf2 root <hash>'; run 'update-grub'.")]


_grub_fn = None


# ---------------------------------------------------------------- SC-009
@register("SC-009", "Authentication log files world-readable", CATEGORY)
def check_authlog_perms(ctx):
    candidates = ["/var/log/auth.log", "/var/log/secure", "/var/log/btmp",
                  "/var/log/wtmp", "/var/log/lastlog", "/var/log/faillog"]
    out, oks, found = [], [], 0
    for p in candidates:
        st = ctx.stat(p)
        if st is None:
            continue
        found += 1
        if is_world_readable(st):
            out.append(Finding("SC-009", _log_fn.check_name, CATEGORY, "VULNERABLE",
                               "LOW", 2.7, "%s (mode %s)" % (p, mode_str(st)),
                               "authentication log world-readable",
                               "Auth logs contain usernames, source IPs, SSH keys "
                               "fingerprints and command history - useful "
                               "reconnaissance data for any local attacker.",
                               "Tighten: 'sudo chmod 640 <log>' with root:<adm|utmp> "
                               "ownership, and configure rsyslog "
                               "('$FileCreateMode 0640')."))
        else:
            oks.append("%s (mode %s)" % (p, mode_str(st)))
    if out:
        return out
    if found:
        return [secure_finding(_log_fn, "; ".join(oks[:5]),
                               "%d auth/audit log files checked; none world-readable"
                               % found,
                               "Authentication logs are not readable by other "
                               "users.")]
    return [skipped_finding(_log_fn, "/var/log",
                            "no authentication log files present/readable "
                            "(fresh container or restricted access).")]


_log_fn = None


# module-level aliases used inside the check functions
_sshk_fn = check_ssh_key_perms
_hist_fn = check_history_creds
_wr_fn = check_world_readable_creds
_hc_fn = check_hardcoded_secrets
_env_fn = check_env_files
_dk_fn = check_docker_socket
_cron_fn = check_cron_files
_grub_fn = check_grub_password
_log_fn = check_authlog_perms

CHECKS = [check_ssh_key_perms, check_history_creds, check_world_readable_creds,
          check_hardcoded_secrets, check_env_files, check_docker_socket,
          check_cron_files, check_grub_password, check_authlog_perms]
