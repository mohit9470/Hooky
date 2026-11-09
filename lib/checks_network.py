#!/usr/bin/env python3
"""Hooky - Network Exposure & Services audit module (NW-xxx)."""

import os
import re
from .core import (register, Finding, secure_finding, skipped_finding,
                   info_finding, read_file, cap_lines, sanitize)

CATEGORY = "Network Exposure"

# port -> (label, severity, score)
RISKY_PORTS = {
    "21":    ("FTP (cleartext file transfer)", "MEDIUM", 6.5),
    "23":    ("Telnet (cleartext remote shell)", "HIGH", 8.6),
    "69":    ("TFTP (unauthenticated file transfer)", "HIGH", 8.0),
    "111":   ("rpcbind/portmapper (RPC service enumeration + amplification)", "HIGH", 7.5),
    "512":   ("rexec (cleartext remote execution)", "HIGH", 8.4),
    "513":   ("rlogin (cleartext remote login)", "HIGH", 8.4),
    "514":   ("rsh/syslog (cleartext remote shell or unauthenticated syslog)", "MEDIUM", 6.6),
    "873":   ("rsync daemon (unauthenticated unless configured)", "MEDIUM", 6.0),
    "1099":  ("Java RMI registry (deserialization exposure)", "MEDIUM", 6.3),
    "2049":  ("NFS daemon (network file share)", "MEDIUM", 6.8),
    "3306":  ("MySQL/MariaDB (database service)", "MEDIUM", 5.4),
    "3389":  ("RDP (remote desktop)", "MEDIUM", 5.6),
    "5432":  ("PostgreSQL (database service)", "MEDIUM", 5.4),
    "5900":  ("VNC (remote desktop, often unencrypted)", "MEDIUM", 6.5),
    "5901":  ("VNC (remote desktop, often unencrypted)", "MEDIUM", 6.5),
    "6379":  ("Redis (no authentication by default)", "HIGH", 7.4),
    "9200":  ("Elasticsearch HTTP API (often unauthenticated)", "MEDIUM", 6.3),
    "11211": ("Memcached (reflection/amplification DDoS vector)", "MEDIUM", 6.5),
    "27017": ("MongoDB (often unauthenticated)", "MEDIUM", 6.3),
    "1900":  ("SSDP/UPnP (amplification vector)", "LOW", 3.2),
}


def _parse_sshd_effective(ctx):
    """Return dict of first-wins effective sshd settings + file:line map."""
    base = "/etc/ssh/sshd_config"
    if not os.path.exists(base):
        return None
    cfg, locs = {}, {}

    def feed(path, depth=0):
        data = read_file(path)
        if data is None or depth > 3:
            return
        for i, raw in enumerate(data.splitlines()):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"(?i)^Include\s+(\S+)", line)
            if m and depth < 3:
                inc = m.group(1)
                if not inc.startswith("/"):
                    inc = "/etc/ssh/" + inc
                import glob as _g
                for f2 in sorted(_g.glob(inc)):
                    feed(f2, depth + 1)
                continue
            m = re.match(r"(?i)^([A-Za-z]\S+)\s+(.+?)\s*$", line)
            if m:
                key, val = m.group(1).lower(), m.group(2)
                if key not in cfg:
                    cfg[key] = val
                    locs[key] = "%s:%d" % (path, i + 1)

    feed(base)
    return cfg, locs


# ---------------------------------------------------------------- NW-001
@register("NW-001", "Risky or legacy services listening", CATEGORY)
def check_risky_listeners(ctx):
    rows = ctx.listeners()
    if not rows:
        return [skipped_finding(_risky_fn, "network sockets",
                                "Could not enumerate listening sockets (ss/netstat "
                                "unavailable or returned nothing).")]
    hits, info = [], []
    for r in rows:
        tag = "%s %s:%s %s" % (r["proto"], r["host"] or "*", r["port"],
                               ("(" + r["process"] + ")") if r["process"] else "")
        if r["port"] in RISKY_PORTS:
            hits.append((r["port"], tag))
        else:
            info.append(tag)
    out = []
    seen_ports = {}
    for port, tag in hits:
        seen_ports[port] = seen_ports.get(port, 0) + 1
    for port, count in seen_ports.items():
        label, sev, score = RISKY_PORTS[port]
        tags = [t for p, t in hits if p == port]
        out.append(Finding("NW-001", _risky_fn.check_name, CATEGORY, "VULNERABLE",
                           sev, score, "listening socket port %s" % port,
                           "%d listener(s): %s" % (count, "; ".join(tags[:4])),
                           "%s is listening on this host. %s"
                           % (label,
                              {"HIGH": "This service transmits data or accepts "
                                       "commands without authentication or "
                                       "encryption and is a frequent initial "
                                       "access vector.",
                               "MEDIUM": "If this service is not intentionally "
                                         "published, it widens the attack surface "
                                         "and may expose data or provide a "
                                         "privilege-escalation path.",
                               "LOW": "Review whether this service is required."}[sev]),
                           {"HIGH": "Stop and mask the service ('sudo systemctl "
                                    "disable --now <unit>') unless there is a "
                                    "documented need; replace cleartext protocols "
                                    "with SSH/HTTPS equivalents.",
                            "MEDIUM": "If required, bind it to localhost or a "
                                      "management network, enable authentication "
                                      "and TLS, and restrict access with the host "
                                      "firewall. Otherwise disable it.",
                            "LOW": "Confirm the service is required and restrict "
                                   "its exposure."}[sev]))
    inv, _t = cap_lines(sorted(info), 15)
    out.append(info_finding(_risky_fn, "listening sockets",
                            "%d listening endpoints in total. Non-flagged:\n%s"
                            % (len(rows), inv),
                            "Full listener inventory for your records - each entry "
                            "is a reachable surface from the networks this host is "
                            "attached to.",
                            ""))
    return out


_risky_fn = None


# ---------------------------------------------------------------- NW-002
@register("NW-002", "Services bound to all interfaces (0.0.0.0 / ::)", CATEGORY)
def check_world_binds(ctx):
    rows = ctx.listeners()
    if not rows:
        return [skipped_finding(_bind_fn, "network sockets",
                                "Could not enumerate listening sockets.")]
    binds = []
    for r in rows:
        if r["host"] in ("0.0.0.0", "::", "*") or r["host"].endswith(":*"):
            binds.append(r)
    if not binds:
        loop = [r for r in rows if r["host"] in ("127.0.0.1", "::1")]
        return [secure_finding(_bind_fn, "listening sockets",
                               "no 0.0.0.0/:: binds; %d loopback-only listener(s)"
                               % len(loop),
                               "All services are bound to loopback only - they are "
                               "not reachable from the network.")]
    out = []
    for r in binds[:12]:
        sev, score = ("LOW", 2.0) if r["port"] == "22" else ("MEDIUM", 5.1)
        tag = "%s %s:%s %s" % (r["proto"], r["host"], r["port"],
                               ("(" + r["process"] + ")") if r["process"] else "")
        out.append(Finding("NW-002", _bind_fn.check_name, CATEGORY, "VULNERABLE",
                           sev, score, "%s:%s (%s)" % (r["host"], r["port"], r["proto"]),
                           "world-exposed listener: " + tag,
                           "This service accepts connections on every network "
                           "interface, including any public-facing one. Anything "
                           "not meant to be published should be loopback- or "
                           "firewall-restricted.",
                           ("SSH on all interfaces is common - confirm firewall "
                            "rules restrict source addresses if possible. " if sev == "LOW" else "") +
                           "Rebind to 127.0.0.1 where the client is local, or "
                           "restrict exposure with nftables/ufw/security-group rules."))
    if len(binds) > 12:
        out[-1].evidence += "\n... (%d more world-exposed listeners)" % (len(binds) - 12)
    return out


_bind_fn = None


# ---------------------------------------------------------------- NW-003
@register("NW-003", "Host firewall active and configured", CATEGORY)
def check_firewall(ctx):
    indicators = []
    rc, out, _ = ctx.run(["ufw", "status"], timeout=10)
    if rc == 0 and "Status: active" in out:
        return [secure_finding(_fw_fn, "ufw", out.strip().splitlines()[0],
                               "UFW firewall is active.")]
    rc, out, _ = ctx.run(["firewall-cmd", "--state"], timeout=10)
    if rc == 0 and "running" in out:
        return [secure_finding(_fw_fn, "firewalld", "firewalld is running",
                               "firewalld is active on this host.")]
    rc, out, _ = ctx.run(["nft", "list", "ruleset"], timeout=15)
    if rc == 0 and out.strip():
        lines = len(out.splitlines())
        return [secure_finding(_fw_fn, "nftables ruleset",
                               "ruleset contains %d lines" % lines,
                               "An nftables ruleset is loaded.")]
    rc, out, _ = ctx.run(["iptables", "-L", "-n"], timeout=15)
    if rc == 0 and out.strip():
        rules = [l for l in out.splitlines() if l and not l.startswith(("Chain", "target"))]
        if len(rules) > 2:
            return [secure_finding(_fw_fn, "iptables",
                                   "%d active rules" % len(rules),
                                   "iptables carries an active ruleset.")]
    # readable config indicators (non-root)
    cfg = read_file("/etc/ufw/ufw.conf")
    if cfg and "ENABLED=yes" in cfg:
        return [secure_finding(_fw_fn, "/etc/ufw/ufw.conf", "ENABLED=yes",
                               "UFW is configured to be enabled (live state "
                               "requires root to confirm).")]
    if ctx.is_root:
        return [Finding("NW-003", _fw_fn.check_name, CATEGORY, "VULNERABLE",
                        "HIGH", 7.5, "host firewall (nftables/iptables/ufw/firewalld)",
                        "No active firewall detected: ufw absent/inactive, no "
                        "firewalld, empty or missing nftables/iptables rulesets.",
                        "Without a host firewall every listening service is exposed "
                        "to every attached network, and lateral movement after a "
                        "single compromise is unobstructed.",
                        "Enable a default-deny firewall: 'sudo ufw default deny "
                        "incoming && sudo ufw allow 22/tcp && sudo ufw enable' "
                        "(Debian/Ubuntu) or define an nftables/iptables INPUT policy "
                        "of DROP with explicit accepts for published services.")]
    # non-root, no tooling available
    tools_missing = []
    for t in ("ufw", "firewall-cmd", "nft", "iptables"):
        rc, _, _ = ctx.run(["which", t], timeout=5)
        if rc != 0:
            tools_missing.append(t)
    if len(tools_missing) >= 3:
        return [Finding("NW-003", _fw_fn.check_name, CATEGORY, "VULNERABLE",
                        "MEDIUM", 5.0, "host firewall tooling",
                        "No firewall management tooling found in PATH (%s)."
                        % ", ".join(tools_missing),
                        "No host firewall can be confirmed on this machine. In a "
                        "container this is often intentional (firewalling happens "
                        "on the host), but for servers an active host firewall is a "
                        "required control.",
                        "If this is a container: confirm network policy on the "
                        "container host / orchestrator instead. If it is a server: "
                        "install and enable ufw or nftables with a default-deny "
                        "inbound policy.")]
    return [skipped_finding(_fw_fn, "host firewall",
                            "Firewall live state requires root privileges "
                            "(ufw/iptables/nft query denied). Re-run as root.")]


_fw_fn = None


# ---------------------------------------------------------------- NW-004
@register("NW-004", "SSH daemon: direct root login permitted", CATEGORY)
def check_sshd_root_login(ctx):
    parsed = _parse_sshd_effective(ctx)
    if parsed is None:
        return [skipped_finding(_root_fn, "/etc/ssh/sshd_config",
                                "OpenSSH server configuration not found on this "
                                "host (sshd not installed).")]
    cfg, locs = parsed
    val = cfg.get("permitrootlogin", "prohibit-password").lower()
    loc = locs.get("permitrootlogin", "/etc/ssh/sshd_config (default)")
    if val == "yes":
        return [Finding("NW-004", _root_fn.check_name, CATEGORY, "VULNERABLE",
                        "HIGH", 7.2, loc,
                        "PermitRootLogin %s" % cfg.get("permitrootlogin"),
                        "Direct root SSH login is permitted. The root account name "
                        "never needs guessing, so attackers only need one credential "
                        "for full compromise, and every brute-force run in the auth "
                        "log targets the most powerful account.",
                        "Set 'PermitRootLogin no' (or at minimum "
                        "'prohibit-password' with keys only) in sshd_config and "
                        "reload sshd: 'sudo systemctl reload sshd'.")]
    if val == "prohibit-password":
        return [info_finding(_root_fn, loc,
                             "PermitRootLogin prohibit-password",
                             "Root can log in with SSH keys but not passwords - "
                             "acceptable per CIS, though 'no' is stricter because "
                             "keys still bypass per-user accountability.",
                             "Set 'PermitRootLogin no' and administer via named "
                             "accounts + sudo.")]
    return [secure_finding(_root_fn, loc, "PermitRootLogin %s" % val,
                           "Direct root SSH login is disabled.")]


_root_fn = None


# ---------------------------------------------------------------- NW-005
@register("NW-005", "SSH daemon: authentication hardening", CATEGORY)
def check_sshd_auth(ctx):
    parsed = _parse_sshd_effective(ctx)
    if parsed is None:
        return [skipped_finding(_auth_fn, "/etc/ssh/sshd_config",
                                "OpenSSH server not installed on this host.")]
    cfg, locs = parsed
    out = []
    if cfg.get("permitemptypasswords", "no").lower() == "yes":
        out.append(Finding("NW-005", _auth_fn.check_name, CATEGORY, "VULNERABLE",
                           "CRITICAL", 9.4,
                           locs.get("permitemptypasswords", "/etc/ssh/sshd_config"),
                           "PermitEmptyPasswords yes",
                           "Accounts without a password can authenticate over SSH "
                           "with a blank password - a direct, keyless entry point.",
                           "Set 'PermitEmptyPasswords no' and reload sshd."))
    try:
        mat = int(cfg.get("maxauthtries", "6"))
    except ValueError:
        mat = 6
    if mat > 6:
        out.append(Finding("NW-005", _auth_fn.check_name, CATEGORY, "VULNERABLE",
                           "LOW", 2.9, locs.get("maxauthtries", "/etc/ssh/sshd_config (default)"),
                           "MaxAuthTries %d (recommend <= 6)" % mat,
                           "A high attempt limit extends the time online "
                           "brute-forcing can run per connection.",
                           "Set 'MaxAuthTries 4' (or <= 6) in sshd_config."))
    lgt = cfg.get("logingracetime", "120")
    try:
        if int(lgt) > 60 or int(lgt) == 0:
            out.append(Finding("NW-005", _auth_fn.check_name, CATEGORY, "VULNERABLE",
                               "LOW", 2.5, locs.get("logingracetime", "/etc/ssh/sshd_config (default)"),
                               "LoginGraceTime %s (recommend <= 60s)" % lgt,
                               "Long grace periods hold unauthenticated sessions "
                               "open, enabling connection-exhaustion DoS.",
                               "Set 'LoginGraceTime 30' (<= 60)."))
    except ValueError:
        pass
    if cfg.get("x11forwarding", "no").lower() == "yes":
        out.append(Finding("NW-005", _auth_fn.check_name, CATEGORY, "VULNERABLE",
                           "LOW", 2.2, locs.get("x11forwarding", "/etc/ssh/sshd_config (default)"),
                           "X11Forwarding yes",
                           "X11 forwarding extends the trusted-X-cookie attack "
                           "surface (keylogging, screen capture) on servers that "
                           "never need GUI apps.",
                           "Set 'X11Forwarding no' unless required."))
    if cfg.get("allowtcpforwarding", "yes").lower() not in ("no", "local"):
        out.append(Finding("NW-005", _auth_fn.check_name, CATEGORY, "VULNERABLE",
                           "LOW", 2.4, locs.get("allowtcpforwarding", "/etc/ssh/sshd_config (default)"),
                           "AllowTcpForwarding yes",
                           "TCP forwarding lets valid accounts tunnel to internal "
                           "networks, bypassing network segmentation controls.",
                           "Set 'AllowTcpForwarding no' for hosts acting only as "
                           "endpoints."))
    if cfg.get("ignorerhosts", "yes").lower() == "no":
        out.append(Finding("NW-005", _auth_fn.check_name, CATEGORY, "VULNERABLE",
                           "MEDIUM", 5.7, locs.get("ignorerhosts", "/etc/ssh/sshd_config (default)"),
                           "IgnoreRhosts no",
                           "Per-user .rhosts/.shosts trust files are honoured, "
                           "bypassing password authentication silently.",
                           "Set 'IgnoreRhosts yes'."))
    if not out:
        return [secure_finding(_auth_fn, "/etc/ssh/sshd_config",
                               "PermitEmptyPasswords=%s MaxAuthTries=%s "
                               "X11Forwarding=%s" % (cfg.get("permitemptypasswords", "no"),
                                                     cfg.get("maxauthtries", "6"),
                                                     cfg.get("x11forwarding", "no")),
                               "SSH authentication settings meet the hardening "
                               "baseline.")]
    return out


_auth_fn = None


# ---------------------------------------------------------------- NW-006
@register("NW-006", "SSH daemon: weak cryptographic algorithms", CATEGORY)
def check_sshd_crypto(ctx):
    parsed = _parse_sshd_effective(ctx)
    if parsed is None:
        return [skipped_finding(_cry_fn, "/etc/ssh/sshd_config",
                                "OpenSSH server not installed on this host.")]
    cfg, locs = parsed
    out = []
    checks = [
        ("ciphers", ("arcfour", "3des", "cbc", "blowfish", "cast", "rijndael"),
         "Ciphers", "weak ciphers (single-DES/3DES/ARCFOUR/CBC modes) are "
                    "practical to attack and leak plaintext structure"),
        ("macs", ("md5", "96", "sha1", "ripemd"),
         "MACs", "MD5/96-bit and truncated-SHA1 MACs no longer provide "
                 "reliable integrity against modern attackers"),
        ("kexalgorithms", ("group1", "sha1", "group14-sha1", "diffie-hellman-group1"),
         "KexAlgorithms", "1024-bit group1/SHA-1 key exchange falls to "
                          "state-sponsored computation budgets"),
    ]
    for key, weak_tokens, label, why in checks:
        val = cfg.get(key)
        if not val:
            continue  # unset => modern OpenSSH defaults
        low = val.lower()
        found = [t for t in weak_tokens if t in low]
        if found:
            out.append(Finding("NW-006", _cry_fn.check_name, CATEGORY, "VULNERABLE",
                               "MEDIUM", 6.0, locs.get(key, "/etc/ssh/sshd_config"),
                               "%s %s  -> weak entries: %s" % (label, val, ", ".join(found)),
                               "The SSH %s list explicitly includes %s." % (label.lower(), why),
                               "Rebuild the algorithm list keeping only modern "
                               "entries, e.g. Ciphers chacha20-poly1305@openssh.com,"
                               "aes256-gcm@openssh.com and MACs "
                               "hmac-sha2-512-etm@openssh.com; KexAlgorithms "
                               "curve25519-sha256."))
    if not out:
        return [secure_finding(_cry_fn, "/etc/ssh/sshd_config",
                               "no explicitly configured weak Ciphers/MACs/Kex found "
                               "(unset values use modern OpenSSH defaults)",
                               "SSH cryptographic negotiation uses the vendor's "
                               "hardened defaults.")]
    return out


_cry_fn = None


# ---------------------------------------------------------------- NW-007
@register("NW-007", "Legacy cleartext network packages installed", CATEGORY)
def check_legacy_net_pkgs(ctx):
    pkgs = ctx.installed_packages()
    if not pkgs:
        return [skipped_finding(_leg_fn, "package database",
                                "No dpkg/rpm package database available.")]
    bad_pkgs = {
        "telnetd": "telnet server", "telnet": "telnet client",
        "inetd": "internet superserver", "openbsd-inetd": "internet superserver",
        "rsh-server": "rsh server", "rsh-client": "rsh client",
        "rsh-redone-server": "rsh server", "rsh-redone-client": "rsh client",
        "rlogin": "rlogin client", "ypserv": "NIS server",
        "nis": "NIS client/server", "tftpd": "tftp server",
        "tftpd-hpa": "tftp server", "atftpd": "tftp server",
        "talk": "talk client", "talkd": "talk server", "xinetd": "extended "
        "internet superserver",
    }
    found = [p for p in bad_pkgs if p in pkgs]
    if found:
        ev = "\n".join("%s (%s) version %s" % (p, bad_pkgs[p], pkgs[p]) for p in sorted(found))
        return [Finding("NW-007", _leg_fn.check_name, CATEGORY, "VULNERABLE",
                        "HIGH", 7.6, "installed packages: " + ", ".join(sorted(found)),
                        ev,
                        "These legacy remote-access protocols transmit everything - "
                        "including passwords - in cleartext and lack any meaningful "
                        "authentication hardening. They are scanned for by every "
                        "mass-scanning botnet.",
                        "Remove them: 'sudo apt-get purge " + " ".join(sorted(found)) +
                        "' and use SSH-based alternatives (scp/sftp/rsync-over-ssh).")]
    return [secure_finding(_leg_fn, "package database",
                           "no telnet/rsh/NIS/talk/tftp packages installed",
                           "No legacy cleartext remote-access packages are present.")]


_leg_fn = None


# ---------------------------------------------------------------- NW-008
@register("NW-008", "NFS exports permissive (world-exported / no_root_squash)", CATEGORY)
def check_nfs_exports(ctx):
    data = read_file("/etc/exports")
    if data is None:
        return [secure_finding(_nfs_fn, "/etc/exports", "file not present",
                               "No NFS exports configured on this host.")]
    out = []
    for i, line in enumerate(data.splitlines()):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "no_root_squash" in s:
            out.append(Finding("NW-008", _nfs_fn.check_name, CATEGORY, "VULNERABLE",
                               "HIGH", 8.0, "/etc/exports:%d" % (i + 1), s,
                               "no_root_squash maps remote root to local root on this "
                               "export - any compromised client gives its root full "
                               "control of the shared data.",
                               "Remove no_root_squash (use root_squash, the default) "
                               "and restrict exports to named hosts/CIDRs."))
        elif re.search(r"[\s*]\*?\s*\(.*(rw|insecure)", s) or s.split()[-1].startswith("*"):
            out.append(Finding("NW-008", _nfs_fn.check_name, CATEGORY, "VULNERABLE",
                               "MEDIUM", 6.8, "/etc/exports:%d" % (i + 1), s,
                               "Export is world-readable/writable ('*'): any host on "
                               "any attached network can mount this share.",
                               "Replace '*' with explicit host lists or CIDRs and "
                               "prefer 'ro' over 'rw'."))
    if not out:
        return [secure_finding(_nfs_fn, "/etc/exports", data.strip()[:300] or "(empty)",
                               "NFS exports, if any, are host-scoped and squashed.")]
    return out


_nfs_fn = None


# ---------------------------------------------------------------- NW-009
@register("NW-009", "Network interfaces in promiscuous mode", CATEGORY)
def check_promisc(ctx):
    data = ctx.cat("/proc/net/dev") or ""
    flags = ctx.cat("/sys/class/net/*/flags")  # placeholder, not used
    prom = []
    try:
        for name in os.listdir("/sys/class/net"):
            f = "/sys/class/net/%s" % name
            fl = ctx.cat(f + "/flags")
            if fl:
                try:
                    if int(fl.strip(), 16) & 0x100:  # IFF_PROMISC
                        prom.append(name)
                except ValueError:
                    pass
    except OSError:
        pass
    if prom:
        return [Finding("NW-009", _prom_fn.check_name, CATEGORY, "VULNERABLE",
                        "LOW", 3.1, "/sys/class/net/" + ", ".join(prom),
                        "interfaces in promiscuous mode: %s" % ", ".join(prom),
                        "Promiscuous mode makes the NIC capture traffic not "
                        "addressed to the host. Legitimate for monitors/IDS, but on "
                        "a normal server it can indicate a packet sniffer "
                        "(tcpdump/wireshark implant) collecting credentials.",
                        "Confirm the cause ('ip link show <iface>'; check for "
                        "running capture processes 'ps aux | grep -E \"tcpdump|"
                        "tshark|dumpcap\"'). Disable with 'sudo ip link set <iface> "
                        "promisc off' if unintended.")]
    return [secure_finding(_prom_fn, "/sys/class/net",
                           "no interfaces with IFF_PROMISC flag",
                           "No interface is capturing foreign traffic; no passive "
                           "sniffer is attached to the host.")]


_prom_fn = None


# module-level aliases used inside the check functions
_risky_fn = check_risky_listeners
_bind_fn = check_world_binds
_fw_fn = check_firewall
_root_fn = check_sshd_root_login
_auth_fn = check_sshd_auth
_cry_fn = check_sshd_crypto
_leg_fn = check_legacy_net_pkgs
_nfs_fn = check_nfs_exports
_prom_fn = check_promisc

CHECKS = [check_risky_listeners, check_world_binds, check_firewall,
          check_sshd_root_login, check_sshd_auth, check_sshd_crypto,
          check_legacy_net_pkgs, check_nfs_exports, check_promisc]
