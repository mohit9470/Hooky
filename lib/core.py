#!/usr/bin/env python3
"""
Hooky core library - data model, system helpers and check registry.

Hooky is a cross-platform vulnerability audit and reporting toolkit.
Everything in this module is dependency-free (Python standard library only).
"""

import os
import re
import pwd
import socket
import platform
import subprocess
import time
from datetime import datetime, timezone

TOOL_NAME = "Hooky"
TOOL_VERSION = "2.1.0"
CVE_DB_DATE = "2026-11"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                  "INFO": 4, "SECURE": 5, "SKIPPED": 6}
STATUS_ORDER = {"VULNERABLE": 0, "SECURE": 1, "INFO": 2, "SKIPPED": 3}

SEV_SCORE_BANDS = "Critical 9.0-10.0 | High 7.0-8.9 | Medium 4.0-6.9 | Low 0.1-3.9"

BACKPORT_CAVEAT = (
    "OFFLINE SIGNATURE MATCH: this result comes from Hooky's built-in CVE "
    "version database (snapshot {dbdate}). Distribution vendors frequently "
    "backport security fixes without changing the upstream version number, so "
    "an installed version matching this rule is NOT proof of exploitation. "
    "Cross-check the vendor security tracker / 'apt-get changelog {pkg}' "
    "before remediation decisions."
)


class Finding(object):
    """A single result of one audit test (may be VULNERABLE/SECURE/INFO/SKIPPED).

    ``host`` is 'local' for the Linux controller itself or the Windows host
    name when the finding came from a remote Hooky Windows agent.
    """
    __slots__ = ("check_id", "name", "category", "status", "severity", "score",
                 "location", "evidence", "description", "remediation", "host")

    def __init__(self, check_id, name, category, status, severity, score,
                 location, evidence, description, remediation, host="local"):
        self.check_id = check_id
        self.name = name
        self.category = category
        self.status = status
        self.severity = severity
        self.score = float(score)
        self.location = location or "system-wide"
        self.evidence = evidence or ""
        self.description = description or ""
        self.remediation = remediation or ""
        self.host = host or "local"

    def to_dict(self):
        return {
            "check_id": self.check_id, "test_name": self.name,
            "category": self.category, "status": self.status,
            "severity": self.severity, "severity_score": self.score,
            "location": self.location, "evidence": self.evidence,
            "description": self.description, "remediation": self.remediation,
            "host": self.host,
        }


def register(check_id, name, category):
    """Decorator that tags a check function with its catalogue metadata."""
    def deco(fn):
        fn.check_id = check_id
        fn.check_name = name
        fn.check_category = category
        return fn
    return deco


def secure_finding(fn, location, evidence, note):
    return Finding(fn.check_id, fn.check_name, fn.check_category,
                   "SECURE", "INFO", 0.0, location, evidence, note,
                   "No action required.")


def info_finding(fn, location, evidence, note, remediation=""):
    return Finding(fn.check_id, fn.check_name, fn.check_category,
                   "INFO", "INFO", 0.0, location, evidence, note, remediation)


def skipped_finding(fn, location, reason):
    return Finding(fn.check_id, fn.check_name, fn.check_category,
                   "SKIPPED", "INFO", 0.0, location, "", reason,
                   "Re-run in a suitable environment (e.g. with root privileges) "
                   "to execute this test.")


# --------------------------------------------------------------------------- #
#  Audit context
# --------------------------------------------------------------------------- #

class AuditContext(object):
    """Carries privilege info, caches and safe subprocess helpers."""

    def __init__(self, quick=False):
        self.quick = quick
        self.is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
        try:
            self.user = pwd.getpwuid(os.geteuid()).pw_name
        except Exception:
            self.user = str(os.geteuid())
        self.started = time.time()
        self._find_cache = {}
        self._listeners_cache = None
        self._packages_cache = None

    # -- process helpers -------------------------------------------------- #
    def run(self, cmd, timeout=30, shell=False):
        """Run a command and return (rc, stdout, stderr). Never raises."""
        try:
            if shell:
                p = subprocess.run(cmd, shell=True, capture_output=True,
                                   text=True, timeout=timeout)
            else:
                p = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout)
            return p.returncode, p.stdout or "", p.stderr or ""
        except FileNotFoundError:
            return 127, "", "command not found"
        except subprocess.TimeoutExpired:
            return 124, "", "timeout after %ss" % timeout
        except Exception as exc:  # pragma: no cover - defensive
            return 1, "", "error: %r" % (exc,)

    # -- file helpers ------------------------------------------------------ #
    def cat(self, path, max_bytes=262144):
        try:
            with open(path, "rb") as fh:
                return fh.read(max_bytes).decode("utf-8", "replace")
        except Exception:
            return None

    def stat(self, path):
        try:
            return os.stat(path, follow_symlinks=False)
        except Exception:
            return None

    # -- cached expensive scans -------------------------------------------- #
    def find(self, expr, roots=None, timeout=None, max_results=20000):
        """Cached wrapper around find(1). expr is the predicate, e.g.
        '-type f -perm -0002'."""
        key = " ".join(roots or []) + "||" + expr
        if key in self._find_cache:
            return self._find_cache[key]
        if timeout is None:
            timeout = 30 if self.quick else 110
        roots = roots if roots else real_fs_roots(self)
        cmd = ["find"] + list(roots) + ["-xdev", "(", ]
        for i, p in enumerate(FIND_PRUNE_DIRS):
            if i:
                cmd.append("-o")
            cmd += ["-path", p]
        cmd += [")", "-prune", "-o"] + expr.split() + ["-print"]
        rc, out, _err = self.run(cmd, timeout=timeout)
        lines = [ln for ln in out.splitlines() if ln.strip()][:max_results]
        self._find_cache[key] = lines
        return lines

    def listeners(self):
        """Parsed listening sockets via ss(8) or netstat(8)."""
        if self._listeners_cache is not None:
            return self._listeners_cache
        rows = []
        rc, out, _ = self.run(["ss", "-tulnpH"], timeout=20)
        if rc == 0 and out.strip():
            rows = _parse_ss(out)
        else:
            rc, out, _ = self.run(["netstat", "-tulnp"], timeout=20)
            if rc == 0:
                rows = _parse_netstat(out)
        self._listeners_cache = rows
        return rows

    def installed_packages(self):
        """dict name -> version for the installed package set."""
        if self._packages_cache is not None:
            return self._packages_cache
        pkgs = {}
        rc, out, _ = self.run(["dpkg-query", "-W",
                               "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"],
                              timeout=60)
        if rc == 0 and out.strip():
            for line in out.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and "ii" in parts[2][:3]:
                    pkgs[parts[0].strip()] = parts[1].strip()
        else:
            rc, out, _ = self.run(["rpm", "-qa", "--qf",
                                   "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=60)
            if rc == 0:
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) == 2:
                        pkgs[parts[0].strip()] = parts[1].strip()
        self._packages_cache = pkgs
        return pkgs


FIND_PRUNE_DIRS = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker",
                   "/var/lib/containerd", "/var/lib/kubelet", "/boot/efi")

_REAL_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs",
            "reiserfs", "overlay", "jfs", "vfat", "exfat", "ntfs3")


def real_fs_roots(ctx):
    """Top-level mount points of real filesystems (for -xdev scanning)."""
    data = ctx.cat("/proc/mounts") or ""
    mounts = []
    for line in data.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        _dev, mnt, fstype = parts[0], parts[1], parts[2]
        if fstype not in _REAL_FS:
            continue
        if any(mnt.startswith(p + "/") or mnt == p for p in FIND_PRUNE_DIRS):
            continue
        if mnt in ("/boot/efi", "/"):
            continue
        mounts.append(mnt)
    tops = []
    for mnt in sorted(mounts):
        if not any(mnt == t or mnt.startswith(t.rstrip("/") + "/") for t in tops):
            tops.append(mnt)
    return tops or ["/"]


def _parse_ss(out):
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, state, _rq, _sq, local = parts[0], parts[1], parts[2], parts[3], parts[4]
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        host, _sep, port = local.rpartition(":")
        rows.append({"proto": proto, "state": state, "host": host,
                     "port": port, "process": proc})
    return rows


def _parse_netstat(out):
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] not in ("tcp", "tcp6", "udp", "udp6"):
            continue
        proto, local = parts[0], parts[5] if len(parts) > 5 else parts[3]
        if len(parts) > 6 and parts[6].startswith("LISTEN") or "LISTEN" in line[:20]:
            state = "LISTEN"
        else:
            state = ""
        proc = ""
        m = re.search(r'(\S+/\d+|\d+/(\S+))\s*$', line)
        if m:
            proc = m.group(1)
        host, _sep, port = local.rpartition(":")
        rows.append({"proto": proto, "state": state or "LISTEN", "host": host,
                     "port": port, "process": proc})
    return rows


# --------------------------------------------------------------------------- #
#  Parsing helpers
# --------------------------------------------------------------------------- #

def read_file(path, max_bytes=262144):
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes).decode("utf-8", "replace")
    except Exception:
        return None


def parse_colon_file(path):
    """Parse /etc/passwd-style files -> list of field-lists, or None."""
    data = read_file(path)
    if data is None:
        return None
    out = []
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line.split(":"))
    return out


def parse_kv_file(path):
    """Parse KEY=value or 'KEY VALUE' config files -> dict (last wins)."""
    data = read_file(path)
    if data is None:
        return None
    kv = {}
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][\w.\-]*)\s*[= ]\s*(\S+)\s*$", line)
        if m:
            kv[m.group(1)] = m.group(2).strip('"\'')
    return kv


def read_sysctl(ctx, key):
    rc, out, _ = ctx.run(["sysctl", "-n", key], timeout=5)
    if rc == 0 and out.strip():
        return out.strip().split()[0]
    val = ctx.cat("/proc/sys/" + key.replace(".", "/"))
    if val is not None:
        return val.strip().split()[0] if val.strip() else None
    return None


# --------------------------------------------------------------------------- #
#  Permission helpers
# --------------------------------------------------------------------------- #

def mode_str(st):
    return format(st.st_mode & 0o7777, "04o")


def is_world_writable(st):
    return bool(st.st_mode & 0o002)


def is_group_writable(st):
    return bool(st.st_mode & 0o020)


def is_world_readable(st):
    return bool(st.st_mode & 0o004)


def is_group_readable(st):
    return bool(st.st_mode & 0o040)


def has_sticky(st):
    return bool(st.st_mode & 0o1000)


def is_suid(st):
    return bool(st.st_mode & 0o4000)


def is_sgid(st):
    return bool(st.st_mode & 0o2000)


def owner_names(st):
    try:
        u = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        u = str(st.st_uid)
    try:
        import grp as _grp
        g = _grp.getgrgid(st.st_gid).gr_name
    except Exception:
        g = str(st.st_gid)
    return "%s:%s" % (u, g)


# --------------------------------------------------------------------------- #
#  Debian/RPM version comparison (subset of dpkg --compare-versions)
# --------------------------------------------------------------------------- #

def _ver_str_cmp(a, b):
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        # non-digit part
        while i < la and j < lb and not a[i].isdigit() and not b[j].isdigit():
            ca, cb = a[i], b[j]
            if ca != cb:
                va = -1 if ca == "~" else (ord(ca) if ca.isalpha() else ord(ca) + 256)
                vb = -1 if cb == "~" else (ord(cb) if cb.isalpha() else ord(cb) + 256)
                return -1 if va < vb else 1
            i += 1
            j += 1
        if i < la and not a[i].isdigit():
            return -1 if a[i] == "~" else 1
        if j < lb and not b[j].isdigit():
            return 1 if b[j] == "~" else -1
        # digit part
        ma = re.match(r"\d*", a[i:])
        mb = re.match(r"\d*", b[j:])
        na, nb = ma.group(), mb.group()
        ia = int(na) if na else 0
        ib = int(nb) if nb else 0
        if ia != ib:
            return -1 if ia < ib else 1
        i += len(na)
        j += len(nb)
    return 0


def vercmp(v1, v2):
    """Return -1/0/1 comparing two Debian-style version strings."""
    def split_epoch(v):
        m = re.match(r"^(?:(\d+):)?(.*)$", v)
        return int(m.group(1)) if m.group(1) else 0, m.group(2)

    def split_rev(v):
        up, _sep, rev = v.rpartition("-")
        return up, rev

    e1, r1 = split_epoch(v1)
    e2, r2 = split_epoch(v2)
    if e1 != e2:
        return -1 if e1 < e2 else 1
    u1, d1 = split_rev(r1)
    u2, d2 = split_rev(r2)
    c = _ver_str_cmp(u1, u2)
    if c:
        return c
    return _ver_str_cmp(d1, d2)


# --------------------------------------------------------------------------- #
#  Text sanitising
# --------------------------------------------------------------------------- #

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")


def sanitize(text, max_len=600, single_line=False):
    if text is None:
        return ""
    t = str(text).replace("\t", "    ")
    if single_line:
        t = _CTRL.sub(" ", t)
        t = re.sub(r"\s+", " ", t).strip()
    else:
        t = _CTRL.sub("\n", t)
    return t[:max_len]


def cap_lines(lines, n):
    """Return (joined_text, total) capping to n lines with a note."""
    total = len(lines)
    shown = lines[:n]
    txt = "\n".join(shown)
    if total > n:
        txt += "\n... (%d more entries not shown)" % (total - n)
    return txt, total


# --------------------------------------------------------------------------- #
#  System metadata
# --------------------------------------------------------------------------- #

def _human_uptime(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return "%d days %d h %d min" % (d, h, m)
    if h:
        return "%d h %d min" % (h, m)
    return "%d min" % m


def collect_metadata(ctx):
    md = {}
    md["hostname"] = socket.gethostname()
    try:
        md["fqdn"] = socket.getfqdn()
    except Exception:
        md["fqdn"] = md["hostname"]
    md["user"] = ctx.user
    md["privileged"] = ctx.is_root
    md["kernel"] = platform.release()
    md["arch"] = platform.machine()

    orl = parse_kv_file("/etc/os-release") or {}
    md["os"] = orl.get("PRETTY_NAME") or orl.get("NAME") or platform.system()
    md["os_id"] = (orl.get("ID") or "").lower()
    md["os_version"] = orl.get("VERSION_ID", "")
    md["os_codename"] = ""
    if "VERSION_CODENAME" in orl:
        md["os_codename"] = orl["VERSION_CODENAME"]

    # hardware model / virtualisation
    model = None
    for p in ("/sys/class/dmi/id/product_name",
              "/proc/device-tree/model",
              "/sys/devices/virtual/dmi/id/product_name"):
        val = ctx.cat(p)
        if val:
            model = val.strip("\x00\n ")
            break
    if model is None:
        if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
            model = "Containerised environment (Docker/Kubernetes)"
        else:
            model = "Unknown / not exposed by this platform"
    md["hardware_model"] = model

    virt = "bare-metal"
    rc, out, _ = ctx.run(["systemd-detect-virt"], timeout=5)
    if rc == 0 and out.strip():
        virt = out.strip()
    elif os.path.exists("/.dockerenv"):
        virt = "docker"
    elif os.path.exists("/run/.containerenv"):
        virt = "podman"
    md["virtualization"] = virt

    mach = ctx.cat("/etc/machine-id")
    md["machine_id"] = mach.strip()[:12] if mach else "n/a"

    cpu_model = "n/a"
    cpuinfo = ctx.cat("/proc/cpuinfo") or ""
    for line in cpuinfo.splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    md["cpu"] = cpu_model
    md["cpu_count"] = os.cpu_count() or 0

    meminfo = ctx.cat("/proc/meminfo") or ""
    m = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
    md["memory"] = "%.1f GB" % (int(m.group(1)) / 1048576.0) if m else "n/a"

    rc, out, _ = ctx.run(["hostname", "-I"], timeout=5)
    ips = out.split() if rc == 0 and out.strip() else []
    md["ip"] = ips[0] if ips else "n/a"

    up = ctx.cat("/proc/uptime")
    md["uptime"] = _human_uptime(float(up.split()[0])) if up else "n/a"

    md["audit_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    md["tool"] = "%s %s" % (TOOL_NAME, TOOL_VERSION)
    md["python"] = platform.python_version()
    return md
