#!/usr/bin/env python3
"""Hooky - Windows system audit module (WIN-xxx).

These checks do NOT read the local Linux host. They consume the JSON blob
produced by the Hooky Windows agent (windows/hooky-agent.ps1),
which is collected either by the Linux controller over SSH (--windows),
received through the HTTP hook collector (--hook), or imported manually
(--windows-import).

Every check is read-only and works purely on the agent's collected data, so
the whole Windows audit can be run, tested and reported offline.
"""

import json
import os
import re
import time
import traceback
from datetime import datetime, timezone

from .core import (register, Finding, secure_finding, info_finding,
                   skipped_finding, sanitize)

WH = "Windows Hardening"
WA = "Windows Accounts"
WN = "Windows Network"
WU = "Windows Updates & AV"


# --------------------------------------------------------------------------- #
#  Context wrapper around one agent result
# --------------------------------------------------------------------------- #

class WinContext(object):
    """Wraps a parsed Windows agent result and exposes its collectors."""

    def __init__(self, result):
        self.result = result or {}
        self.collectors = self.result.get("collectors") or {}
        self.host = self.result.get("computer") or "windows-host"

    def col(self, name):
        """Return collector data, or None when missing/failed/empty."""
        c = self.collectors.get(name)
        if not c or not c.get("ok"):
            return None
        return c.get("data")

    def col_error(self, name):
        c = self.collectors.get(name)
        if c is None:
            return "collector '%s' is missing from the agent output" % name
        if not c.get("ok"):
            return "collector '%s' failed on the Windows host: %s" % (
                name, sanitize(c.get("error"), 200, single_line=True))
        return "collector '%s' returned no data" % name


def load_result_file(path):
    """Load + validate a Windows agent JSON file -> WinContext."""
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except Exception as exc:
        raise ValueError("cannot read Windows agent result '%s': %s" % (path, exc))
    if not isinstance(data, dict) or "collectors" not in data:
        raise ValueError(
            "'%s' is not a Hooky Windows agent result (expected a JSON "
            "object with a 'collectors' key, schema hooky-agent/1)" % path)
    return WinContext(data)


def host_metadata(wctx):
    """Build a report-friendly metadata dict for one Windows target."""
    s = wctx.col("system") or {}
    lis = wctx.col("listeners") or []
    ip = "n/a"
    for row in lis:
        a = str(row.get("local_address", ""))
        if a and not a.startswith("127.") and a not in ("::1", "0.0.0.0", "::"):
            ip = a
            break
    comp = str(s.get("computer_name") or wctx.host)
    dom = str(s.get("domain") or "")
    fqdn = ("%s.%s" % (comp, dom)) if (dom and s.get("part_of_domain")) else comp
    build = s.get("build_number")
    ubr = s.get("ubr")
    kernel = "build %s.%s" % (build, ubr) if build else "n/a"
    elevated = bool(wctx.result.get("elevated"))
    return {
        "hostname": comp,
        "fqdn": fqdn,
        "platform": "Windows",
        "os": s.get("os_caption") or "Windows",
        "os_id": "windows",
        "os_version": "%s (%s)" % (s.get("os_version", ""), s.get("display_version") or ""),
        "kernel": kernel,
        "arch": s.get("os_arch") or "n/a",
        "hardware_model": ("%s %s" % (s.get("manufacturer") or "",
                                      s.get("model") or "")).strip() or "n/a",
        "virtualization": "n/a (Windows agent)",
        "machine_id": dom or "standalone",
        "ip": ip,
        "cpu": s.get("cpu") or "n/a",
        "cpu_count": s.get("cpu_count") or 0,
        "memory": ("%s GB" % mem) if (mem := s.get("memory_gb")) else "n/a",
        "uptime": ("last boot %s" % s.get("last_boot")) if s.get("last_boot") else "n/a",
        "user": "Hooky agent (%s)" % ("elevated" if elevated else "non-elevated"),
        "privileged": elevated,
        "audit_time": wctx.result.get("collected_at") or "n/a",
        "tool": "Hooky Windows agent %s" % wctx.result.get("agent_version", ""),
        "python": "PowerShell %s" % wctx.result.get("ps_version", ""),
    }


# --------------------------------------------------------------------------- #
#  Small parsing helpers
# --------------------------------------------------------------------------- #

def _as_int(v):
    """Parse ints from registry values or 'net accounts' values ('90 days')."""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        m = re.match(r"\s*(\d+)", v)
        if m:
            return int(m.group(1))
    return None


def _day_diff(datestr):
    """Days between today and a 'yyyy-mm-dd...' string, or None."""
    if not datestr:
        return None
    try:
        d = datetime.strptime(str(datestr)[:10], "%Y-%m-%d")
        return (datetime.now(timezone.utc) - d.replace(tzinfo=timezone.utc)).days
    except Exception:
        return None


def _f(fn, status, sev, score, loc, ev, desc, rem):
    return Finding(fn.check_id, fn.check_name, fn.check_category,
                   status, sev, score, loc, ev, desc, rem)


def _na(fname, kv):
    """'net accounts' parsed value lookup (English locale keys)."""
    for k, v in kv.items():
        if k.lower() == fname.lower():
            return v
    return None


# --------------------------------------------------------------------------- #
#  WA - Windows Accounts
# --------------------------------------------------------------------------- #

@register("WIN-001", "Local password policy (net accounts)", WA)
def check_password_policy(wctx):
    data = wctx.col("net_accounts")
    if not data or not data.get("parsed"):
        return [skipped_finding(check_password_policy, "net accounts",
                                wctx.col_error("net_accounts") +
                                " (or non-English output - see the agent's raw "
                                "capture in the JSON result)")]
    kv, out = data["parsed"], []
    raw = data.get("raw") or []

    def rawline(key):
        for ln in raw:
            if key.lower() in ln.lower():
                return ln.strip()
        return key

    minlen = _as_int(_na("Minimum password length", kv))
    if minlen is not None and minlen < 8:
        out.append(_f(check_password_policy, "VULNERABLE",
                      "CRITICAL" if minlen == 0 else "HIGH",
                      8.5 if minlen == 0 else 7.2,
                      "net accounts: Minimum password length",
                      rawline("Minimum password length"),
                      "The local password policy allows passwords shorter than 8 "
                      "characters%s Short or empty passwords are cracked in "
                      "seconds by offline attacks once a hash database leaks, and "
                      "they open the door to brute-force attacks against RDP, SMB "
                      "and any locally exposed logon interface."
                      % (" (i.e. blank passwords are acceptable)." if minlen == 0 else "."),
                      "Raise the minimum length to at least 12-14 characters:\n"
                      "1. secpol.msc > Security Settings > Account Policies > Password Policy\n"
                      "2. Set 'Minimum password length' to 14 (CIS Benchmark recommendation)\n"
                      "3. Or via GPO: Computer Configuration\\Policies\\Windows Settings"
                      "\\Security Settings\\Account Policies\\Password Policy"))
    hist = _as_int(_na("Length of password history maintained", kv))
    if hist is not None and hist < 5:
        out.append(_f(check_password_policy, "VULNERABLE", "MEDIUM",
                      4.5 if hist else 5.2,
                      "net accounts: Length of password history maintained",
                      rawline("Length of password history maintained"),
                      "Fewer than 5 remembered passwords lets users immediately "
                      "recycle old passwords, defeating password rotation after a "
                      "suspected credential leak.",
                      "Set 'Enforce password history' to 24 or more passwords "
                      "remembered (CIS Benchmark recommendation)."))
    maxage = _na("Maximum password age", kv)
    maxd = _as_int(maxage)
    if maxd == 0 or (isinstance(maxage, str) and maxage.strip().lower().startswith("never")):
        out.append(_f(check_password_policy, "VULNERABLE", "MEDIUM", 4.6,
                      "net accounts: Maximum password age",
                      rawline("Maximum password age"),
                      "Passwords never expire. Old, possibly-compromised "
                      "credentials remain valid indefinitely.",
                      "Set 'Maximum password age' to 90 days or less "
                      "(CIS Benchmark: 365 or less, industry standard 90)."))
    elif maxd is not None and maxd > 90:
        out.append(_f(check_password_policy, "VULNERABLE", "LOW", 3.5,
                      "net accounts: Maximum password age",
                      rawline("Maximum password age"),
                      "Password maximum age exceeds 90 days, prolonging the "
                      "usable life of any leaked credential.",
                      "Reduce 'Maximum password age' to 90 days or less."))
    if not out:
        return [secure_finding(check_password_policy, "net accounts",
                               "\n".join(str(x) for x in raw[:12]),
                               "Local password policy meets the tested baselines "
                               "(min length >= 8, history >= 5, max age <= 90 days).")]
    return out


@register("WIN-002", "Account lockout policy", WA)
def check_lockout(wctx):
    data = wctx.col("net_accounts")
    if not data or not data.get("parsed"):
        return [skipped_finding(check_lockout, "net accounts",
                                wctx.col_error("net_accounts") +
                                " (or non-English output)")]
    kv, raw = data["parsed"], (data.get("raw") or [])
    out = []

    def rawline(key):
        for ln in raw:
            if key.lower() in ln.lower():
                return ln.strip()
        return key

    thr = _na("Lockout threshold", kv)
    thrv = _as_int(thr)
    if thrv == 0 or (isinstance(thr, str) and thr.strip().lower().startswith("never")):
        out.append(_f(check_lockout, "VULNERABLE", "HIGH", 7.4,
                      "net accounts: Lockout threshold",
                      rawline("Lockout threshold"),
                      "Accounts never lock out, so unlimited online password "
                      "guessing against SMB, RDP, WinRM and any published "
                      "service is possible (password spraying).",
                      "Set 'Account lockout threshold' to 10 or fewer invalid "
                      "attempts, 'reset counter' to 15 minutes and lockout "
                      "duration to 15 minutes or more."))
    else:
        dur = _as_int(_na("Lockout duration", kv))
        obs = _as_int(_na("Lockout observation window", kv))
        if dur is not None and obs is not None and (dur < 15 or obs < 15):
            out.append(_f(check_lockout, "VULNERABLE", "LOW", 3.3,
                          "net accounts: Lockout duration / observation window",
                          rawline("Lockout duration") + " | " +
                          rawline("Lockout observation window"),
                          "The lockout counter resets or unlocks faster than "
                          "15 minutes, weakening the protection against "
                          "slow password spraying.",
                          "Set both 'Account lockout duration' and 'Reset "
                          "account lockout counter after' to 15 minutes or more."))
    if not out:
        return [secure_finding(check_lockout, "net accounts",
                               "\n".join(str(x) for x in raw[:12]),
                               "Account lockout policy is enabled (threshold > 0 "
                               "with adequate duration/window).")]
    return out


@register("WIN-003", "Guest account enabled", WA)
def check_guest(wctx):
    data = wctx.col("local_users")
    if not data or not data.get("users"):
        return [skipped_finding(check_guest, "local user database",
                                wctx.col_error("local_users"))]
    for u in data["users"]:
        name = str(u.get("name", ""))
        if name.lower() == "guest":
            if u.get("enabled"):
                ev = "Account '%s': Enabled=%s, PasswordRequired=%s" % (
                    name, u.get("enabled"), u.get("password_required"))
                sev, score = ("CRITICAL", 8.6) if not u.get("password_required") \
                    else ("HIGH", 7.6)
                return [_f(check_guest, "VULNERABLE", sev, score,
                           "Local user database: account 'Guest'",
                           ev,
                           "The built-in Guest account is enabled. Its SID is "
                           "well known and it is a classic target for "
                           "unauthenticated access; combined with 'password not "
                           "required' it can allow anonymous logon.",
                           "Disable the Guest account:\n"
                           "1. Get-LocalUser -Name Guest | Disable-LocalUser\n"
                           "2. Or: Computer Management > Local Users and Groups "
                           "> Users > Guest > Properties > tick 'Account is disabled'")]
            return [secure_finding(check_guest, "Local user database: 'Guest'",
                                   "Account 'Guest' is disabled.",
                                   "The built-in Guest account is disabled.")]
    return [info_finding(check_guest, "Local user database",
                         "No account named 'Guest' present.",
                         "The built-in Guest account does not exist (it may "
                         "have been removed by a hardening image).")]


@register("WIN-004", "Built-in Administrator account status", WA)
def check_admin_account(wctx):
    data = wctx.col("local_users")
    if not data or not data.get("users"):
        return [skipped_finding(check_admin_account, "local user database",
                                wctx.col_error("local_users"))]
    for u in data["users"]:
        name = str(u.get("name", ""))
        if name.lower() == "administrator":
            if u.get("enabled") and not u.get("password_required"):
                return [_f(check_admin_account, "VULNERABLE", "CRITICAL", 9.5,
                           "Local user database: account '%s'" % name,
                           "Account '%s': Enabled=%s, PasswordRequired=%s"
                           % (name, u.get("enabled"), u.get("password_required")),
                           "The built-in Administrator account is active and "
                           "allowed to have a BLANK password. This account owns "
                           "everything on the box, cannot be locked out by "
                           "default, and is the first target of every "
                           "brute-force and pass-the-hash attack.",
                           "1. Disable it: Get-LocalUser Administrator | Disable-LocalUser\n"
                           "2. If it must stay enabled, set a strong password and "
                           "enforce 'Password required': Set-LocalUser Administrator "
                           "-PasswordNeverExpires $false; net user Administrator /passwordreq:yes\n"
                           "3. Prefer named, individually-auditable admin accounts "
                           "plus LAPS for local admin rotation.")]
            if u.get("enabled"):
                return [_f(check_admin_account, "VULNERABLE", "MEDIUM", 5.3,
                           "Local user database: account '%s'" % name,
                           "Account '%s' is enabled (well-known SID -500)."
                           % name,
                           "The built-in Administrator account is enabled. Its "
                           "SID is identical on every Windows machine, which "
                           "makes it a predictable target even when renamed.",
                           "1. Disable the built-in account and use named admin "
                           "accounts with MFA.\n"
                           "2. If required by legacy software, keep it enabled "
                           "but rotate its password automatically with Windows "
                           "LAPS.")]
            return [secure_finding(check_admin_account, "Local user database: 'Administrator'",
                                   "Built-in Administrator account is disabled.",
                                   "The built-in Administrator account is disabled.")]
    return [info_finding(check_admin_account, "Local user database",
                         "No account named 'Administrator' found.",
                         "The built-in Administrator account was not found "
                         "(possibly renamed - verify manually).")]


@register("WIN-005", "Local Administrators group membership", WA)
def check_admin_group(wctx):
    data = wctx.col("local_users")
    if not data or "groups" not in data:
        return [skipped_finding(check_admin_group, "local group 'Administrators'",
                                wctx.col_error("local_users"))]
    members = data["groups"].get("Administrators") or []
    names = [str(m.get("name", "")) for m in members if m]
    listing = ", ".join(names) if names else "(no members returned)"
    out = [info_finding(check_admin_group, "local group 'Administrators'",
                        "%d member(s): %s" % (len(names), listing),
                        "Inventory of privileged accounts. Every member has "
                        "full control of this host - keep this list minimal "
                        "and review it regularly.",
                        "")]
    svc_like = [n for n in names
                if re.search(r"(svc|service|sql|backup|agent|jenkins|ansible|deploy)",
                             n, re.I)]
    if svc_like:
        out.append(_f(check_admin_group, "VULNERABLE", "MEDIUM", 5.6,
                      "local group 'Administrators'",
                      "Service-like account(s) in Administrators: %s"
                      % ", ".join(svc_like),
                      "Accounts that look like service accounts hold "
                      "interactive admin rights. Service credentials are "
                      "frequently stored in configs and are a common path "
                      "from a low-privilege foothold to full admin.",
                      "Remove service accounts from Administrators; grant them "
                      "only the specific rights they need (e.g. via local "
                      "policies or managed service accounts gMSA)."))
    if len(names) > 8:
        out.append(_f(check_admin_group, "VULNERABLE", "LOW", 3.3,
                      "local group 'Administrators'",
                      "%d members: %s" % (len(names), listing),
                      "More than 8 accounts hold local admin rights, which "
                      "multiplies the credential-theft surface (each admin "
                      "logon caches hashes in LSASS).",
                      "Reduce standing admin access; adopt tiered admin "
                      "accounts and just-in-time elevation."))
    return out


# --------------------------------------------------------------------------- #
#  WH - Windows Hardening
# --------------------------------------------------------------------------- #

@register("WIN-006", "User Account Control (UAC) configuration", WH)
def check_uac(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("uac"):
        return [skipped_finding(check_uac, r"HKLM:\...\Policies\System",
                                wctx.col_error("registry"))]
    uac, out = reg["uac"], []
    loc = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    ena = _as_int(uac.get("EnableLUA"))
    if ena == 0:
        out.append(_f(check_uac, "VULNERABLE", "CRITICAL", 9.2,
                      loc + ":EnableLUA",
                      "EnableLUA = 0 (User Account Control fully disabled)",
                      "UAC is switched off. Every process - including malware "
                      "launched by a normal user - runs with full "
                      "administrative token, and all UAC-based privilege "
                      "boundaries are gone.",
                      "Re-enable UAC:\n"
                      "1. Set-ItemProperty -Path '%s' -Name EnableLUA -Value 1\n"
                      "2. Reboot the machine (required)." % loc))
    elif ena is None:
        out.append(info_finding(check_uac, loc + ":EnableLUA",
                                "EnableLUA not set (defaults to enabled on client SKUs).",
                                "UAC is likely at its default (enabled) state.",
                                ""))
    consent = _as_int(uac.get("ConsentPromptBehaviorAdmin"))
    if consent == 0:
        out.append(_f(check_uac, "VULNERABLE", "HIGH", 7.6,
                      loc + ":ConsentPromptBehaviorAdmin",
                      "ConsentPromptBehaviorAdmin = 0 (elevate without prompting)",
                      "Administrators are elevated silently with no consent "
                      "prompt. Any code that can trigger an auto-elevating "
                      "binary gains admin rights without user interaction.",
                      "Set 'User Account Control: Behavior of the elevation "
                      "prompt for administrators' to 'Prompt for consent on "
                      "the secure desktop' (value 5, default) or 2."))
    psd = _as_int(uac.get("PromptOnSecureDesktop"))
    if psd == 0 and ena != 0:
        out.append(_f(check_uac, "VULNERABLE", "LOW", 3.2,
                      loc + ":PromptOnSecureDesktop",
                      "PromptOnSecureDesktop = 0",
                      "UAC prompts appear on the interactive desktop, where "
                      "malware can click the prompt or spoof it to phish "
                      "admin approval.",
                      "Set 'User Account Control: Switch to the secure "
                      "desktop when prompting for elevation' to Enabled."))
    latfp = _as_int(uac.get("LocalAccountTokenFilterPolicy"))
    if latfp == 1:
        out.append(_f(check_uac, "VULNERABLE", "MEDIUM", 5.8,
                      loc + ":LocalAccountTokenFilterPolicy",
                      "LocalAccountTokenFilterPolicy = 1",
                      "Remote connections with local accounts receive the "
                      "FULL admin token, disabling the remote-UAC "
                      "restriction. This makes local-admin password reuse "
                      "and pass-the-hash attacks against SMB/PSRemoting "
                      "trivially effective.",
                      "Delete the value or set it to 0:\n"
                      "Remove-ItemProperty -Path '%s' -Name LocalAccountTokenFilterPolicy"
                      % loc))
    if not out:
        return [secure_finding(check_uac, loc,
                               "EnableLUA=1, ConsentPromptBehaviorAdmin=%s, "
                               "PromptOnSecureDesktop=%s"
                               % (consent, psd),
                               "UAC is enabled with an administrator consent "
                               "prompt on the secure desktop.")]
    return out


@register("WIN-007", "LSA Protection (RunAsPPL)", WH)
def check_lsa_ppl(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("lsa"):
        return [skipped_finding(check_lsa_ppl, r"HKLM:\...\Control\Lsa",
                                wctx.col_error("registry"))]
    val = _as_int(reg["lsa"].get("RunAsPPL"))
    loc = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL"
    if val == 1:
        return [secure_finding(check_lsa_ppl, loc, "RunAsPPL = 1",
                               "LSASS runs as a protected process, blocking "
                               "most credential-dumping tooling from reading "
                               "memory.")]
    if val == 0:
        return [_f(check_lsa_ppl, "VULNERABLE", "HIGH", 7.9, loc,
                   "RunAsPPL = 0 (LSA protection explicitly disabled)",
                   "LSASS is NOT a protected process. Mimikatz-style tools "
                   "can read every credential cached in memory - domain "
                   "admin credentials included - from any local admin "
                   "session.",
                   "Enable LSA protection:\n"
                   "1. Set-ItemProperty -Path '%s' -Name RunAsPPL -Value 1 -Type DWord\n"
                   "2. Reboot.\n"
                   "3. Verify with Get-Process lsass -IncludeUserName "
                   "(should be 'Protected' via PPL flag in Process Explorer)." % loc)]
    return [_f(check_lsa_ppl, "VULNERABLE", "LOW", 3.8, loc,
               "RunAsPPL is not configured (key absent)",
               "No explicit LSA Protection policy. On Windows 11 22H2+ / "
               "Server 2025 it is on by default; on older builds LSASS is "
               "readable by local admins.",
               "Set RunAsPPL=1 under HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa "
               "and reboot (Windows 11 22H2+ can rely on the default).")]


@register("WIN-008", "NTLM / LAN Manager authentication level", WH)
def check_ntlm(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("lsa"):
        return [skipped_finding(check_ntlm, r"HKLM:\...\Control\Lsa",
                                wctx.col_error("registry"))]
    lsa, loc = reg["lsa"], r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    out = []
    lm = _as_int(lsa.get("LmCompatibilityLevel"))
    if lm in (0, 1):
        out.append(_f(check_ntlm, "VULNERABLE", "HIGH", 8.1,
                      loc + ":LmCompatibilityLevel",
                      "LmCompatibilityLevel = %d (LM and/or NTLMv1 permitted)"
                      % lm,
                      "The host still accepts LM/NTLMv1 authentication. Both "
                      "are cryptographically broken and crackable in minutes; "
                      "an attacker who can force authentication (e.g. via "
                      " coercion to an SMB listener) captures crackable hashes.",
                      "Set 'Network security: LAN Manager authentication level' "
                      "to 'Send NTLMv2 responses only. Refuse LM & NTLMv1' "
                      "(value 3) or higher."))
    elif lm == 2:
        out.append(_f(check_ntlm, "VULNERABLE", "MEDIUM", 6.1,
                      loc + ":LmCompatibilityLevel",
                      "LmCompatibilityLevel = 2 (LM refused, NTLMv1 accepted)",
                      "NTLMv1 authentication is still accepted. NTLMv1 "
                      "response hashes are routinely cracked.",
                      "Raise LmCompatibilityLevel to 3 or higher."))
    nolm = _as_int(lsa.get("NoLMHash"))
    if nolm == 0:
        out.append(_f(check_ntlm, "VULNERABLE", "MEDIUM", 5.0,
                      loc + ":NoLMHash",
                      "NoLMHash = 0 (LM hashes are stored)",
                      "The SAM/NTDS still stores legacy LM password hashes, "
                      "which reveal the password's first 7 characters almost "
                      "instantly when cracked.",
                      "Set NoLMHash=1 (or via GPO 'Do not store LAN Manager "
                      "hash value on next password change') and force a "
                      "password change."))
    for name, sev, score in (("RestrictAnonymous", "LOW", 3.4),
                             ("RestrictAnonymousSAM", "LOW", 3.4)):
        if _as_int(lsa.get(name)) == 0:
            out.append(_f(check_ntlm, "VULNERABLE", sev, score,
                          loc + ":" + name,
                          "%s = 0 (anonymous enumeration permitted)" % name,
                          "Anonymous (null-session) access to SAM accounts "
                          "or shares is allowed, giving attackers a free "
                          "user/asset inventory.",
                          "Set %s=1 under %s." % (name, loc)))
    if not out:
        return [secure_finding(check_ntlm, loc,
                               "LmCompatibilityLevel=%s, NoLMHash=%s, "
                               "RestrictAnonymous=%s"
                               % (lm, nolm, lsa.get("RestrictAnonymous")),
                               "Legacy LM/NTLMv1 authentication is disabled "
                               "(NTLMv2-only) and anonymous enumeration is "
                               "restricted.")]
    return out


@register("WIN-009", "SMBv1 protocol enabled", WH)
def check_smb1(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("smb1"):
        return [skipped_finding(check_smb1,
                                r"HKLM:\...\LanmanServer\Parameters:SMB1",
                                wctx.col_error("registry"))]
    smb = reg["smb1"]
    loc = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1"
    out = []
    if _as_int(smb.get("SMB1")) == 1:
        out.append(_f(check_smb1, "VULNERABLE", "CRITICAL", 9.8, loc,
                      "SMB1 = 1 (SMBv1 server component is ENABLED)",
                      "SMBv1 is enabled. This is the protocol abused by "
                      "EternalBlue (MS17-010) and the WannaCry/NotPetya "
                      "ransomware worms; it has no realistic defense other "
                      "than removal.",
                      "Remove SMBv1 immediately:\n"
                      "1. Set-ItemProperty -Path '%s' -Name SMB1 -Value 0\n"
                      "2. Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\n"
                      "3. Reboot and verify with Get-SmbServerConfiguration | Select EnableSMB1Protocol"
                      % loc))
    if _as_int(smb.get("mrxsmb10_start")) == 0:
        out.append(_f(check_smb1, "VULNERABLE", "HIGH", 7.5,
                      r"HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10:Start",
                      "mrxsmb10 (SMBv1 client driver) Start = 0 (boot start)",
                      "The SMBv1 CLIENT driver is still enabled, so this host "
                      "can connect to - and be relayed against - other "
                      "legacy systems using SMB1.",
                      "Remove the SMB1 client binding:\n"
                      "1. Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart\n"
                      "2. Or: sc.exe config mrxsmb10 start= disabled"))
    if not out:
        return [secure_finding(check_smb1, loc,
                               "SMB1=%s, mrxsmb10 Start=%s"
                               % (smb.get("SMB1"), smb.get("mrxsmb10_start")),
                               "SMBv1 is disabled for both the server and "
                               "client components.")]
    return out


@register("WIN-016", "BitLocker OS volume encryption", WH)
def check_bitlocker(wctx):
    data = wctx.col("bitlocker")
    if not data:
        return [skipped_finding(check_bitlocker, "BitLocker (manage-bde)",
                                wctx.col_error("bitlocker") +
                                " - BitLocker checks need an elevated agent")]
    vols = data.get("volumes") or []
    if not vols:
        raw = data.get("managebde_raw") or []
        text = "\n".join(str(x) for x in raw)
        if "Protection Off" in text:
            return [_f(check_bitlocker, "VULNERABLE", "HIGH", 7.5,
                       "manage-bde -status (OS volume)",
                       "\n".join(str(x) for x in raw[:14]),
                       "BitLocker protection is OFF for the OS volume. Anyone "
                       "with physical access (stolen laptop, datacentre "
                       "disk swap) can read every file offline.",
                       "Enable BitLocker on the OS drive:\n"
                       "1. Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector\n"
                       "2. Add a recovery password: Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector\n"
                       "3. Escrow the recovery key in AD/Azure AD/Intune.")]
        if text.strip():
            return [info_finding(check_bitlocker, "manage-bde -status",
                                 "\n".join(str(x) for x in raw[:14]),
                                 "manage-bde output captured - verify the OS "
                                 "volume shows 'Protection On'.", "")]
        return [skipped_finding(check_bitlocker, "BitLocker (manage-bde)",
                                "No BitLocker volume data returned (needs "
                                "elevation or non-OS edition).")]
    weak = [v for v in vols if str(v.get("protection", "")).lower() != "on"]
    if weak:
        ev = "\n".join("MountPoint=%s status=%s protection=%s encryption=%s%%"
                       % (v.get("mount_point"), v.get("volume_status"),
                          v.get("protection"), v.get("encryption_pct"))
                       for v in vols)
        return [_f(check_bitlocker, "VULNERABLE", "HIGH", 7.5,
                   "; ".join(str(v.get("mount_point")) for v in weak),
                   ev,
                   "One or more volumes (including the OS volume) are not "
                   "BitLocker-protected. Offline attacks against a stolen "
                   "or cloned disk reveal all data.",
                   "1. Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector\n"
                   "2. Escrow recovery keys (AD/Entra/Intune).\n"
                   "3. Check status: Get-BitLockerVolume")]
    return [secure_finding(check_bitlocker,
                           "; ".join(str(v.get("mount_point")) for v in vols),
                           "All volumes report ProtectionStatus=On.",
                           "BitLocker protection is on for the reported volumes.")]


@register("WIN-020", "Service binary paths (unquoted / user-writable)", WH)
def check_service_paths(wctx):
    data = wctx.col("services")
    if data is None:
        return [skipped_finding(check_service_paths, "Win32_Service",
                                wctx.col_error("services"))]
    unquoted, writable = [], []
    _EXE_RE = re.compile(r'^\s*"?([^"*]+?\.(?:exe|dll|sys))"?', re.I)
    for s in data or []:
        path = str(s.get("path_name") or "")
        name = str(s.get("name") or "")
        if not path:
            continue
        m = _EXE_RE.match(path)
        exe = m.group(1) if m else path.strip('"')
        if " " in exe and not path.strip().startswith('"'):
            unquoted.append("%s -> %s (%s)" % (name, path, s.get("state")))
        low = exe.lower()
        if (low.startswith("c:\\users\\") or low.startswith("c:\\temp\\")
                or low.startswith("c:\\windows\\temp\\")
                or low.startswith("c:\\perflogs\\")
                or re.match(r"^c:\\programdata\\[^\\]+$", low)):
            writable.append("%s -> %s (%s)" % (name, path, s.get("state")))
    out = []
    if unquoted:
        out.append(_f(check_service_paths, "VULNERABLE", "HIGH", 7.8,
                      "; ".join(u.split(" -> ")[0] for u in unquoted),
                      "\n".join(unquoted),
                      "Windows services are registered with an UNQUOTED "
                      "binary path containing spaces. Windows will execute "
                      "every prefix before the space as a service first - "
                      "e.g. 'C:\\Program Files\\X\\svc.exe' also tries "
                      "'C:\\Program.exe' - a well-known local privilege "
                      "escalation path.",
                      "1. Re-register the affected services with quoted paths:\n"
                      "   sc.exe config <name> binPath= \"\\\"C:\\path with spaces\\svc.exe\\\"\"\n"
                      "2. Or move the binary to a path without spaces."))
    if writable:
        out.append(_f(check_service_paths, "VULNERABLE", "HIGH", 8.0,
                      "; ".join(w.split(" -> ")[0] for w in writable),
                      "\n".join(writable),
                      "A Windows service runs its binary from a "
                      "user-writable location (C:\\Users, C:\\Temp, "
                      "C:\\Windows\\Temp or a ProgramData root). Any user "
                      "who can write that file inherits the service's "
                      "privileges (often SYSTEM) on next start/reboot.",
                      "1. Move the binary to %ProgramFiles% (admin-only ACLs).\n"
                      "2. Re-point the service: sc.exe config <name> binPath= \"<new path>\"\n"
                      "3. Audit ACLs: icacls \"<old path>\""))
    if not out:
        return [secure_finding(check_service_paths, "Win32_Service (%d services)"
                               % len(data or []),
                               "No unquoted service paths with spaces and no "
                               "services running from user-writable "
                               "directories were found.",
                               "Service binary paths look sound.")]
    return out


@register("WIN-021", "Legacy TLS / SSL protocol versions (SCHANNEL)", WH)
def check_tls(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("tls_server"):
        return [skipped_finding(check_tls,
                                r"HKLM:\...\SCHANNEL\Protocols",
                                wctx.col_error("registry"))]
    tls = reg["tls_server"]
    base = r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    rules = [("SSL 2.0", "CRITICAL", 9.5, "SSL 2.0 is broken beyond repair"),
             ("SSL 3.0", "HIGH", 8.3, "SSL 3.0 is vulnerable to POODLE and is deprecated"),
             ("TLS 1.0", "MEDIUM", 5.9, "TLS 1.0 is deprecated (PCI-DSS prohibits it)"),
             ("TLS 1.1", "MEDIUM", 5.3, "TLS 1.1 is deprecated (RFC 8996)")]
    out = []
    for proto, sev, score, why in rules:
        d = tls.get(proto) or {}
        if _as_int(d.get("Enabled")) == 1:
            out.append(_f(check_tls, "VULNERABLE", sev, score,
                          "%s\\%s\\Server:Enabled" % (base, proto),
                          "%s Server: Enabled = 1 (%s)" % (proto, why),
                          "This legacy protocol is explicitly enabled for "
                          "server-side connections, allowing downgrade "
                          "attacks and modern compliance failures.",
                          "Disable it:\n"
                          "1. Set-ItemProperty -Path '%s\\%s\\Server' -Name Enabled -Value 0\n"
                          "2. Also set DisabledByDefault = 1\n"
                          "3. Reboot." % (base, proto)))
    d12 = tls.get("TLS 1.2") or {}
    if _as_int(d12.get("Enabled")) == 0 and _as_int(d12.get("DisabledByDefault")) == 1:
        out.append(_f(check_tls, "VULNERABLE", "MEDIUM", 5.6,
                      "%s\\TLS 1.2\\Server" % base,
                      "TLS 1.2 Server: Enabled=0, DisabledByDefault=1",
                      "TLS 1.2 is disabled, forcing even modern clients "
                      "onto legacy protocols for inbound connections.",
                      "Enable TLS 1.2 (Enabled=1, DisabledByDefault=0) and reboot."))
    if not out:
        return [secure_finding(check_tls, base,
                               "No legacy protocol is explicitly enabled; "
                               "TLS 1.2 state: %s" % (d12 or "OS default"),
                               "SCHANNEL server protocols show no explicitly "
                               "enabled legacy SSL/TLS version.")]
    return out


@register("WIN-022", "AutoRun / AutoPlay policy", WH)
def check_autorun(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("autorun"):
        return [skipped_finding(check_autorun,
                                r"HKLM:\...\Policies\Explorer:NoDriveTypeAutoRun",
                                wctx.col_error("registry"))]
    val = _as_int(reg["autorun"].get("NoDriveTypeAutoRun"))
    loc = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoDriveTypeAutoRun"
    if val == 255:
        return [secure_finding(check_autorun, loc,
                               "NoDriveTypeAutoRun = 255 (0xFF - AutoRun "
                               "disabled on ALL drive types)",
                               "AutoRun is fully disabled (CIS baseline).")]
    if val is None or val == 0:
        return [_f(check_autorun, "VULNERABLE", "HIGH", 6.5, loc,
                   "NoDriveTypeAutoRun is not configured (AutoRun active)",
                   "With no AutoRun restriction, inserting USB media can "
                   "trigger program execution - the classic BadUSB staging "
                   "technique used in physical intrusions.",
                   "Disable AutoRun on all drives (CIS baseline):\n"
                   "1. Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255\n"
                   "2. Also set GPO 'Turn off Autoplay' = All drives.")]
    return [_f(check_autorun, "VULNERABLE", "MEDIUM", 4.9, loc,
               "NoDriveTypeAutoRun = %d (0x%02X - some drive types still "
               "allow AutoRun)" % (val, val),
               "AutoRun is only partially restricted. On the default 0x91, "
               "removable USB drives still present AutoPlay/AutoRun "
               "options to the user.",
               "Set NoDriveTypeAutoRun = 255 (0xFF) via GPO 'Turn off "
               "Autoplay' = All drives.")]


@register("WIN-023", "Interactive inactivity lock (screen saver)", WH)
def check_screensaver(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("screensaver"):
        return [skipped_finding(check_screensaver,
                                r"HKLM:\...\Control Panel\Desktop (policy)",
                                wctx.col_error("registry"))]
    ss = reg["screensaver"]
    loc = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    active = _as_int(ss.get("ScreenSaveActive"))
    secure = _as_int(ss.get("ScreenSaverIsSecure"))
    timeout = _as_int(ss.get("ScreenSaveTimeOut"))
    if active == 0:
        return [_f(check_screensaver, "VULNERABLE", "LOW", 3.2, loc,
                   "ScreenSaveActive = 0 (screen saver policy disabled)",
                   "Inactivity locking is disabled by policy; an unattended "
                   "session stays unlocked forever.",
                   "Enable the policy 'Password protect the screen saver' and "
                   "set a screen saver timeout <= 900 seconds.")]
    if secure == 0:
        return [_f(check_screensaver, "VULNERABLE", "MEDIUM", 4.4, loc,
                   "ScreenSaverIsSecure = 0 (screen saver without password)",
                   "The screen saver does not require a password, so "
                   "'locking' the console does nothing.",
                   "Enable GPO 'Password protect the screen saver' "
                   "(ScreenSaverIsSecure=1).")]
    if active is None and secure is None:
        return [_f(check_screensaver, "VULNERABLE", "LOW", 3.1, loc,
                   "No inactivity lock policy defined "
                   "(ScreenSaveActive/ScreenSaverIsSecure not set)",
                   "No group policy enforces a password-protected screen "
                   "saver; users may leave sessions unlocked indefinitely.",
                   "1. GPO: User Configuration\\Administrative Templates\\"
                   "Control Panel\\Personalization\\Enable screen saver + "
                   "Password protect the screen saver\n"
                   "2. Set 'Screen saver timeout' to 900 seconds or less.")]
    if timeout is not None and timeout > 1800:
        return [_f(check_screensaver, "VULNERABLE", "LOW", 3.3, loc,
                   "ScreenSaveTimeOut = %d (> 1800 seconds)" % timeout,
                   "Sessions remain unlocked for more than 30 idle minutes.",
                   "Reduce 'Screen saver timeout' to 900 seconds or less.")]
    return [secure_finding(check_screensaver, loc,
                           "ScreenSaveActive=%s, ScreenSaverIsSecure=%s, "
                           "ScreenSaveTimeOut=%s" % (active, secure, timeout),
                           "A password-protected inactivity lock is enforced "
                           "within an acceptable time window.")]


@register("WIN-024", "PowerShell logging & transcription", WH)
def check_pslogging(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("powershell_logging"):
        return [skipped_finding(check_pslogging,
                                r"HKLM:\...\PowerShell\ScriptBlockLogging",
                                wctx.col_error("registry"))]
    psl = reg["powershell_logging"]
    base = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    out = []
    if _as_int(psl.get("EnableScriptBlockLogging")) != 1:
        out.append(_f(check_pslogging, "VULNERABLE", "MEDIUM", 4.7,
                      base + r"\ScriptBlockLogging:EnableScriptBlockLogging",
                      "EnableScriptBlockLogging is not set to 1",
                      "PowerShell script blocks are not logged, removing the "
                      "single best telemetry source against PowerShell-based "
                      "attacks (encoded downloaders, in-memory loaders).",
                      "1. New-Item -Path '%s\\ScriptBlockLogging' -Force\n"
                      "2. Set-ItemProperty -Path '%s\\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1"
                      % (base, base)))
    if _as_int(psl.get("EnableModuleLogging")) != 1:
        out.append(_f(check_pslogging, "VULNERABLE", "LOW", 3.2,
                      base + r"\ModuleLogging:EnableModuleLogging",
                      "EnableModuleLogging is not set to 1",
                      "PowerShell module pipeline execution is not recorded "
                      "in the Windows Event Log.",
                      "Enable Module Logging via GPO 'Turn on PowerShell "
                      "Module Logging' (log at least Microsoft.* modules)."))
    if _as_int(psl.get("EnableTranscripting")) != 1:
        out.append(_f(check_pslogging, "VULNERABLE", "LOW", 3.0,
                      base + r"\Transcription:EnableTranscripting",
                      "EnableTranscripting is not set to 1",
                      "PowerShell sessions leave no transcript trail of "
                      "commands and output.",
                      "Enable GPO 'Start PowerShell Transcription' with a "
                      "protected output directory."))
    if not out:
        return [secure_finding(check_pslogging, base,
                               "ScriptBlockLogging=%s, ModuleLogging=%s, "
                               "Transcription=%s"
                               % (psl.get("EnableScriptBlockLogging"),
                                  psl.get("EnableModuleLogging"),
                                  psl.get("EnableTranscripting")),
                               "PowerShell auditing (script-block, module "
                               "logging, transcription) is fully enabled.")]
    return out


# --------------------------------------------------------------------------- #
#  WN - Windows Network
# --------------------------------------------------------------------------- #

@register("WIN-010", "Remote Desktop (RDP) & Network Level Authentication", WN)
def check_rdp(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("rdp"):
        return [skipped_finding(check_rdp,
                                r"HKLM:\...\Terminal Server:fDenyTSConnections",
                                wctx.col_error("registry"))]
    rdp = reg["rdp"]
    base = r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    deny = _as_int(rdp.get("fDenyTSConnections"))
    if deny is None:
        return [skipped_finding(check_rdp, base + ":fDenyTSConnections",
                                "RDP enablement not reported by the agent registry "
                                "collector (fDenyTSConnections absent).")]
    if deny == 1:
        return [secure_finding(check_rdp, base + ":fDenyTSConnections",
                               "fDenyTSConnections = 1 (Remote Desktop disabled)",
                               "RDP is disabled on this host.")]
    nla = _as_int(rdp.get("NLA_UserAuthentication"))
    port = _as_int(rdp.get("PortNumber"))
    out = []
    if nla == 0:
        out.append(_f(check_rdp, "VULNERABLE", "HIGH", 8.2,
                      base + r"\WinStations\RDP-Tcp:UserAuthentication",
                      "RDP enabled (fDenyTSConnections=0) with "
                      "UserAuthentication=0 (NLA DISABLED)",
                      "RDP accepts sessions before authentication. This "
                      "exposes pre-auth attack surface (BlueKeep-class "
                      "RCE), enables credential-stuffing without valid "
                      "credentials and makes CredSSP relay possible.",
                      "Require NLA:\n"
                      "1. Set-ItemProperty -Path '%s\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1\n"
                      "2. Or GPO: 'Require user authentication for remote connections...'\n"
                      "3. Restrict 3389 with the firewall to management IPs." % base))
    else:
        out.append(info_finding(check_rdp, base + ":fDenyTSConnections",
                                "RDP enabled with Network Level Authentication "
                                "(UserAuthentication=%s)." % nla,
                                "RDP is protected by NLA. Confirm 3389 is not "
                                "published to the internet (see WIN-012) and "
                                "prefer a VPN/bastion for remote access.", ""))
    if port and port != 3389:
        out.append(info_finding(check_rdp,
                                base + r"\WinStations\RDP-Tcp:PortNumber",
                                "RDP is listening on non-standard port %d." % port,
                                "A non-default RDP port reduces scanner noise "
                                "but is NOT a security control - keep NLA and "
                                "firewall restriction as the real defenses.", ""))
    return out


@register("WIN-011", "Windows Firewall profiles", WN)
def check_firewall(wctx):
    data = wctx.col("firewall")
    if not data:
        return [skipped_finding(check_firewall, "Get-NetFirewallProfile",
                                wctx.col_error("firewall"))]
    profiles = data.get("profiles") or []
    out = []
    for p in profiles:
        name = str(p.get("name", ""))
        if not p.get("enabled"):
            sev = "HIGH"
            score = {"Domain": 7.5, "Private": 7.8}.get(name, 8.2)
            out.append(_f(check_firewall, "VULNERABLE", sev, score,
                          "Get-NetFirewallProfile: %s profile" % name,
                          "Firewall profile '%s': Enabled=False, "
                          "DefaultInboundAction=%s" % (name, p.get("default_inbound")),
                          "The '%s' firewall profile is DISABLED. Every "
                          "listening service on this host becomes reachable "
                          "on the matching network, and lateral movement is "
                          "unrestricted." % name,
                          "Re-enable the profile:\n"
                          "1. Set-NetFirewallProfile -Name %s -Enabled True -DefaultInboundAction Block\n"
                          "2. Review inbound rules that were used while it was off." % name))
    if not profiles:
        raw = data.get("netsh_raw") or []
        text = "\n".join(str(x) for x in raw).lower()
        if "off" in text:
            return [_f(check_firewall, "VULNERABLE", "HIGH", 7.9,
                       "netsh advfirewall show allprofiles state",
                       "\n".join(str(x) for x in raw[:14]),
                       "netsh reports at least one firewall profile OFF.",
                       "Enable all profiles: Set-NetFirewallProfile -Profile * -Enabled True")]
        if text.strip():
            return [info_finding(check_firewall, "netsh advfirewall",
                                 "\n".join(str(x) for x in raw[:14]),
                                 "Firewall state captured via netsh - verify "
                                 "all profiles show ON.", "")]
        return [skipped_finding(check_firewall, "Get-NetFirewallProfile",
                                "No firewall profile data (needs elevation).")]
    if not out:
        return [secure_finding(check_firewall, "Get-NetFirewallProfile",
                               "; ".join("%s=Enabled" % p.get("name")
                                         for p in profiles),
                               "All firewall profiles (Domain/Private/Public) "
                               "are enabled.")]
    return out


RISKY_PORTS = {
    23: ("Telnet server", "CRITICAL", 9.3,
         "Telnet transmits everything - including credentials - in cleartext.",
         "Disable the service: Disable-NetAdapter binding / Uninstall-WindowsFeature Telnet-Server; block port 23 at the firewall."),
    21: ("FTP server", "MEDIUM", 6.5,
         "Classic FTP sends credentials and data unencrypted.",
         "Replace with FTPS/SFTP; if required, restrict with firewall rules."),
    5900: ("VNC server", "HIGH", 7.7,
           "VNC exposes full remote desktop control, often with weak auth.",
           "Disable VNC or tunnel it through SSH/VPN with strong authentication."),
    5800: ("VNC web interface", "HIGH", 7.6,
           "The Java VNC web listener exposes console access via HTTP.",
           "Disable the VNC web listener."),
    5985: ("WinRM HTTP", "MEDIUM", 5.4,
           "WinRM over HTTP (no TLS) accepts remote PowerShell - a favourite lateral-movement channel.",
           "Require HTTPS (5986) and Kerberos, restrict source IPs via firewall, or disable WinRM when unused."),
    3389: ("RDP", "MEDIUM", 6.9,
           "RDP is exposed on a non-loopback address; when combined with disabled NLA it is the #1 ransomware entry point.",
           "Require NLA (see WIN-010) and restrict 3389 to bastion/VPN source IPs."),
}


@register("WIN-012", "Risky listening services exposed on the network", WN)
def check_listeners(wctx):
    rows = wctx.col("listeners")
    if rows is None:
        return [skipped_finding(check_listeners, "Get-NetTCPConnection",
                                wctx.col_error("listeners"))]
    exposed, out, seen = [], [], set()
    for r in rows or []:
        addr = str(r.get("local_address", ""))
        if addr.startswith("127.") or addr == "::1":
            continue
        port = _as_int(r.get("local_port"))
        if port is None:
            continue
        exposed.append("%s:%s (%s)" % (addr, port, r.get("process") or "?"))
        info = RISKY_PORTS.get(port)
        if info and port not in seen:
            seen.add(port)
            label, sev, score, why, rem = info
            out.append(_f(check_listeners, "VULNERABLE", sev, score,
                          "%s:%s -> %s" % (addr, port, r.get("process") or "?"),
                          "%s listening on %s:%s (process: %s)"
                          % (label, addr, port, r.get("process") or "unknown"),
                          why + " Anyone on the network segment can reach it.",
                          rem))
    general = info_finding(
        check_listeners, "Get-NetTCPConnection (non-loopback listeners)",
        "%d non-loopback listener(s): %s" % (len(exposed),
                                             ", ".join(exposed[:12]) +
                                             (" ..." if len(exposed) > 12 else "")),
        "Inventory of services reachable from the network. Verify each one "
        "is required and firewall-restricted.", "")
    return out + [general]


# --------------------------------------------------------------------------- #
#  WU - Windows Updates & AV
# --------------------------------------------------------------------------- #

@register("WIN-013", "Antimalware real-time protection", WU)
def check_av_realtime(wctx):
    d = wctx.col("defender")
    if d:
        out = []
        if d.get("realtime_enabled") is False or d.get("disable_realtime_pref") is True:
            out.append(_f(check_av_realtime, "VULNERABLE", "CRITICAL", 9.4,
                          "Get-MpComputerStatus:RealTimeProtectionEnabled",
                          "RealTimeProtectionEnabled=%s, "
                          "DisableRealtimeMonitoring(pref)=%s"
                          % (d.get("realtime_enabled"),
                             d.get("disable_realtime_pref")),
                          "Microsoft Defender real-time protection is OFF. "
                          "Known malware executes freely; ransomware and "
                          "common loaders land undetected.",
                          "Re-enable real-time protection:\n"
                          "1. Set-MpPreference -DisableRealtimeMonitoring $false\n"
                          "2. Start-Service WinDefend; ensure it is not "
                          "disabled by tampered policy."))
            if d.get("am_running") is False:
                out.append(_f(check_av_realtime, "VULNERABLE", "HIGH", 8.0,
                              "Get-MpComputerStatus:AMServiceEnabled",
                              "AMServiceEnabled=False (antimalware service not running)",
                              "The Defender antimalware service itself is not running.",
                              "Start-Service WinDefend and verify with Get-MpComputerStatus."))
            reduced = [k for k, label in
                       (("behavior_monitor", "behavior monitoring"),
                        ("nis_enabled", "network inspection (NIS)"),
                        ("ioav_enabled", "Office/IE reputation scanning"))
                       if d.get(k) is False]
            if reduced:
                out.append(_f(check_av_realtime, "VULNERABLE", "MEDIUM", 5.5,
                              "Get-MpComputerStatus (reduced protections)",
                              "Disabled: " + ", ".join(reduced),
                              "Secondary Defender protection layers are off: %s."
                              % ", ".join(reduced),
                              "Re-enable each layer with Set-MpPreference "
                              "(e.g. -DisableBehaviorMonitoring $false)."))
        if not out:
            return [secure_finding(check_av_realtime,
                                   "Get-MpComputerStatus",
                                   "RealTimeProtectionEnabled=%s, AMServiceEnabled=%s"
                                   % (d.get("realtime_enabled"), d.get("am_running")),
                                   "Microsoft Defender real-time protection and "
                                   "the antimalware service are active.")]
        return out
    tp = wctx.col("third_party_av")
    if tp and tp.get("products"):
        names = ", ".join(str(p.get("name")) for p in tp["products"])
        return [info_finding(check_av_realtime, "root/SecurityCenter2:AntiVirusProduct",
                             "Third-party antimalware registered: %s" % names,
                             "Defender status is unavailable but a third-party "
                             "AV product is registered. Verify its real-time "
                             "engine is enabled centrally.", "")]
    return [_f(check_av_realtime, "VULNERABLE", "HIGH", 8.4,
               "Defender / SecurityCenter2",
               "No Defender status and no registered antimalware product.",
               "No antimalware product could be detected on this host.",
               "Install/repair Microsoft Defender or a supported third-party "
               "AV and confirm real-time protection is on.")]


@register("WIN-014", "Antimalware signature freshness", WU)
def check_av_signatures(wctx):
    d = wctx.col("defender")
    if not d:
        return [skipped_finding(check_av_signatures,
                                "Get-MpComputerStatus:AntivirusSignatureAge",
                                wctx.col_error("defender"))]
    age = _as_int(d.get("signature_age_days"))
    if age is None:
        return [skipped_finding(check_av_signatures,
                                "Get-MpComputerStatus:AntivirusSignatureAge",
                                "Signature age not reported (engine may be "
                                "replaced by third-party AV).")]
    loc = "Get-MpComputerStatus:AntivirusSignatureAge"
    ev = "signature age = %s day(s), last updated %s, engine %s" % (
        age, d.get("signature_last_updated") or "?",
        d.get("signature_version") or "?")
    if age > 30:
        sev, score = "CRITICAL", 8.7
    elif age > 7:
        sev, score = "HIGH", 7.2
    else:
        return [secure_finding(check_av_signatures, loc, ev,
                               "Antimalware signatures are current (<= 7 days).")]
    return [_f(check_av_signatures, "VULNERABLE", sev, score, loc, ev,
               "Virus signatures are %d days old. Malware released since the "
               "last update sails past static detection." % age,
               "Force an update and fix its schedule:\n"
               "1. Update-MpSignature -UpdateSource MicrosoftUpdateServer\n"
               "2. Verify WSUS/deferral policies are not freezing updates.")]


@register("WIN-015", "Dangerous Defender exclusions", WU)
def check_av_exclusions(wctx):
    d = wctx.col("defender")
    if not d:
        return [skipped_finding(check_av_exclusions, "Get-MpPreference",
                                wctx.col_error("defender"))]
    paths = [str(x) for x in (d.get("exclusion_paths") or [])]
    exts = [str(x) for x in (d.get("exclusion_extensions") or [])]
    procs = [str(x) for x in (d.get("exclusion_processes") or [])]
    if not (paths or exts or procs):
        return [secure_finding(check_av_exclusions, "Get-MpPreference",
                               "No exclusions configured.",
                               "Defender scans everything - no exclusions present.")]
    loc = "Get-MpPreference:ExclusionPath/Extension/Process"
    ev = "paths=%s | extensions=%s | processes=%s" % (paths or "-", exts or "-", procs or "-")
    wild = (any(p.lower().rstrip("\\") in ("c:", "c:\\", "\\", "/") or
                p.rstrip("\\").endswith("*") for p in paths)
            or "*" in exts or "*" in procs)
    if wild:
        return [_f(check_av_exclusions, "VULNERABLE", "HIGH", 7.4, loc, ev,
                   "A wildcard or drive-root exclusion (e.g. C:\\ or *.exe) "
                   "effectively disables antivirus scanning while keeping "
                   "the product 'enabled' - a favourite malware hiding "
                   "technique (used by real ransomware via tampered "
                   "preferences).",
                   "1. Remove wildcard exclusions: Remove-MpPreference -ExclusionPath 'C:\\'\n"
                   "2. Replace with the narrowest possible explicit paths "
                   "justified by vendor documentation.")]
    return [info_finding(check_av_exclusions, loc, ev,
                         "%d exclusion(s) configured - confirm each is "
                         "documented, narrow and still required."
                         % (len(paths) + len(exts) + len(procs)), "")]


@register("WIN-017", "Windows patch freshness & pending reboot", WU)
def check_patches(wctx):
    data = wctx.col("hotfixes")
    out = []
    if not data:
        out.append(skipped_finding(check_patches, "Get-HotFix",
                                   wctx.col_error("hotfixes")))
    else:
        updates = data.get("updates") or []
        latest = None
        for u in updates:
            d = _day_diff(u.get("installed_on"))
            if d is not None and (latest is None or d < latest[0]):
                latest = (d, u)
        if latest is None:
            out.append(_f(check_patches, "VULNERABLE", "HIGH", 7.4,
                          "Get-HotFix",
                          "No installed-update dates reported (%d hotfix objects)."
                          % len(updates),
                          "No update installation dates are available - the "
                          "host may never have been patched or reporting is "
                          "broken.",
                          "1. Verify Windows Update works: usoclient StartScan\n"
                          "2. Confirm WSUS/Azure Update Manager coverage."))
        else:
            days, u = latest
            loc = "Get-HotFix: %s (installed %s)" % (u.get("id"), u.get("installed_on"))
            ev = "Most recent update %s was installed %d day(s) ago (%d updates total)." % (
                u.get("id"), days, len(updates))
            if days > 180:
                out.append(_f(check_patches, "VULNERABLE", "HIGH", 7.6, loc, ev,
                              "The host has not received an update for more "
                              "than 6 months. Every CVE fixed in that window "
                              "is exploitable here, and ransomware groups "
                              "target exactly such stale hosts.",
                              "1. Patch now: usoclient StartScan / StartDownload / StartInstall\n"
                              "2. Investigate why updates stopped (WSUS quota, paused ring, broken service)."))
            elif days > 90:
                out.append(_f(check_patches, "VULNERABLE", "MEDIUM", 5.5, loc, ev,
                              "No update for more than 90 days - patching "
                              "cadence is slipping behind the exploit window.",
                              "Bring the host back into the regular patch cycle."))
            else:
                out.append(secure_finding(check_patches, loc, ev,
                                          "The most recent update is within 90 days."))
    s = wctx.col("system")
    if s and s.get("pending_reboot"):
        pr = s["pending_reboot"]
        pend = [k for k, v in pr.items() if v]
        if pend:
            out.append(_f(check_patches, "VULNERABLE", "MEDIUM", 4.8,
                          "system/pending_reboot: " + ", ".join(pend),
                          "Pending reboot indicators: %s"
                          % ", ".join("%s=True" % k for k in pend),
                          "Updates or servicing are staged but the host has "
                          "not rebooted - installed protections are NOT yet "
                          "active, and reboot storms may be suppressed by "
                          "users.",
                          "Schedule a controlled reboot, then re-run the scan."))
    return out


@register("WIN-018", "Operating system end-of-life status", WU)
def check_eol(wctx):
    s = wctx.col("system")
    if not s:
        return [skipped_finding(check_eol, "Win32_OperatingSystem",
                                wctx.col_error("system"))]
    build = _as_int(s.get("build_number"))
    caption = str(s.get("os_caption") or "Windows")
    loc = "Win32_OperatingSystem:Caption/CurrentBuildNumber"
    ev = "%s (build %s)" % (caption, s.get("build_number"))
    low_cap = caption.lower()
    if build in (7600, 7601) or "windows 7" in low_cap or "server 2008" in low_cap:
        return [_f(check_eol, "VULNERABLE", "CRITICAL", 9.6, loc, ev,
                   "This platform (Windows 7 / Server 2008 R2) left extended "
                   "support on 2020-01-14. No security fixes exist for the "
                   "hundreds of CVEs published since; it will be compromised "
                   "if exposed.",
                   "Migrate to a supported OS immediately; until then isolate "
                   "it from all networks (and document the exception).")]
    if build in (9200, 9600) or "windows 8" in low_cap or "server 2012" in low_cap:
        return [_f(check_eol, "VULNERABLE", "CRITICAL", 9.3, loc, ev,
                   "This platform (Windows 8.1 / Server 2012 R2) is "
                   "end-of-life (extended support ended 2023-10-10) and no "
                   "longer receives security updates.",
                   "Migrate to Windows 11 / Server 2022+; isolate in the "
                   "meantime.")]
    if ("windows 10" in low_cap and "ltsc" not in low_cap and "ltsb" not in low_cap
            and 10240 <= (build or 0) <= 19045):
        return [_f(check_eol, "VULNERABLE", "HIGH", 8.8, loc, ev,
                   "Windows 10 exited support on 2025-10-14 (retail editions). "
                   "Unless this host is covered by ESU/LTSC servicing, it no "
                   "longer receives security updates.",
                   "Upgrade to Windows 11, move to an LTSC/ESU servicing "
                   "track, or isolate the host.")]
    if "windows 10" in low_cap and "ltsc" in low_cap:
        return [info_finding(check_eol, loc, ev,
                             "Windows 10 LTSC - extended servicing applies "
                             "(verify the specific LTSC release date).", "")]
    if "server 2016" in low_cap:
        return [info_finding(check_eol, loc, ev,
                             "Windows Server 2016 - extended support until "
                             "2027-01-12; plan the migration.", "")]
    if "server" in low_cap or "windows 11" in low_cap:
        return [secure_finding(check_eol, loc, ev,
                               "Platform is within its supported servicing "
                               "lifetime (verify Microsoft lifecycle page for "
                               "the exact edition).")]
    return [info_finding(check_eol, loc, ev,
                         "Build not in the local EOL map - verify against "
                         "Microsoft's lifecycle pages.", "")]


@register("WIN-019", "Automatic Windows Update policy", WU)
def check_wu_policy(wctx):
    reg = wctx.col("registry")
    if not reg or not reg.get("wu_policy"):
        return [skipped_finding(check_wu_policy,
                                r"HKLM:\...\WindowsUpdate\AU:NoAutoUpdate",
                                wctx.col_error("registry"))]
    val = _as_int(reg["wu_policy"].get("NoAutoUpdate"))
    loc = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:NoAutoUpdate"
    if val == 1:
        return [_f(check_wu_policy, "VULNERABLE", "HIGH", 7.3, loc,
                   "NoAutoUpdate = 1 (automatic updates DISABLED by policy)",
                   "The host will not install security updates automatically. "
                   "Combined with busy administrators this is how servers go "
                   "years without patches.",
                   "1. Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -Value 0\n"
                   "2. Or manage patching deliberately via WSUS/Azure Update "
                   "Manager with enforced maintenance windows.")]
    return [secure_finding(check_wu_policy, loc,
                           "NoAutoUpdate=%s (automatic updates not disabled)"
                           % val,
                           "Windows Update is not disabled by local policy.")]


# --------------------------------------------------------------------------- #
#  WA - Security auditing (auditpol)
# --------------------------------------------------------------------------- #

@register("WIN-025", "Security auditing policy (auditpol)", WA)
def check_auditpol(wctx):
    data = wctx.col("auditpol")
    if not data:
        return [skipped_finding(check_auditpol, "auditpol /get /category:*",
                                wctx.col_error("auditpol") +
                                " (auditpol requires an elevated agent)")]
    lines = [str(x) for x in (data.get("lines") or []) if str(x).strip()]
    rows = []
    for ln in lines:
        cols = re.split(r"\s{2,}", ln.strip())
        if len(cols) >= 3 and cols[2].strip():
            rows.append((cols[0], cols[1], cols[2]))
    if len(rows) < 5:
        return [skipped_finding(check_auditpol, "auditpol /get /category:*",
                                "auditpol output could not be parsed "
                                "(non-English locale or truncated): %d rows"
                                % len(rows))]
    important = ("logon", "logoff", "account management", "policy change",
                 "process creation", "authentication policy change",
                 "user account management", "other logon/logoff events",
                 "security group management", "plug and play events")
    weak = ["%s / %s = %s" % (c0, c1, c2) for c0, c1, c2 in rows
            if c2.strip().lower() == "no auditing" and c1.lower() in important]
    if weak:
        return [_f(check_auditpol, "VULNERABLE", "MEDIUM", 5.1,
                   "auditpol /get /category:*",
                   "\n".join(weak),
                   "Auditing is disabled (%d subcategories) for core "
                   "security-relevant events such as logon, account "
                   "management or policy change. Intrusions will leave "
                   "no traces." % len(weak),
                   "1. auditpol /set /category:'Logon/Logoff','Account Management','Policy Change' /success:enable /failure:enable\n"
                   "2. Ship Security event log 4624/4625/4720+ to your SIEM.")]
    return [secure_finding(check_auditpol, "auditpol /get /category:*",
                           "No 'No Auditing' entries among %d core subcategories."
                           % len(rows),
                           "Core security auditing (logon, account management, "
                           "policy change) is enabled.")]


# --------------------------------------------------------------------------- #
#  EC - Windows enterprise controls (agent collector 'enterprise')
# --------------------------------------------------------------------------- #

@register("WIN-026", "Local administrator password solution (LAPS)", WH)
def check_laps(wctx):
    data = wctx.col("enterprise")
    if not data or "laps" not in data:
        return [skipped_finding(check_laps, "enterprise collector",
                                "Agent result has no 'enterprise' collector "
                                "- re-run the current agent (>= 1.2.0) on "
                                "this host.")]
    laps = data.get("laps") or {}
    policy = bool(laps.get("windows_laps_policy"))
    legacy = bool(laps.get("legacy_laps_cse"))
    if policy or legacy:
        which = "Windows LAPS policy" if policy else "legacy LAPS CSE (admpwd.dll)"
        return [secure_finding(check_laps, "LAPS",
                               "Detected: %s" % which,
                               "Local administrator passwords are managed "
                               "and rotated per machine.")]
    return [_f(check_laps, "VULNERABLE", "HIGH", 7.0,
               "LAPS (Windows LAPS policy / legacy LAPS CSE)",
               "No LAPS policy key (HKLM\\...\\Policies\\LAPS) and no "
               "legacy LAPS CSE (admpwd.dll) found on this host.",
               "Without LAPS every machine shares the same built-in "
               "administrator password (or a predictable variant). One "
               "compromised workstation hands an attacker the credentials "
               "for the entire fleet - a top-3 finding in most enterprise "
               "AD security reviews (CIS Benchmark, Microsoft security "
               "baseline).",
               "1. Deploy Microsoft LAPS (free, no extra licence):\n"
               "   - Windows 11 22H2+/Server 2025: built-in Windows LAPS\n"
               "   - older: Microsoft LAPS legacy client + GPO\n"
               "2. Enforce via GPO: Computer Configuration\\Policies\\"
               "Administrative Templates\\LAPS (or System/LAPS legacy).\n"
               "3. Verify rotation: Get-LapsDiagnostics / LAPS policy event log.")]


@register("WIN-027", "SMB signing requirement (relay protection)", WH)
def check_smb_signing(wctx):
    data = wctx.col("enterprise")
    if not data or "smb_signing" not in data:
        return [skipped_finding(check_smb_signing, "enterprise collector",
                                "Agent result has no 'enterprise' collector "
                                "- re-run the current agent (>= 1.2.0).")]
    smb = data.get("smb_signing") or {}
    server = smb.get("server_require")
    client = smb.get("client_require")
    if _as_int(server) == 1 and _as_int(client) == 1:
        return [secure_finding(check_smb_signing,
                               "HKLM\\SYSTEM\\...\\LanmanServer/LanmanWorkstation\\Parameters",
                               "RequireSecuritySignature: server=1, client=1",
                               "SMB traffic must be signed - NTLM relay and "
                               "tampering attacks are mitigated.")]
    return [_f(check_smb_signing, "VULNERABLE", "MEDIUM", 5.6,
               "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer"
               "\\Parameters:RequireSecuritySignature",
               "RequireSecuritySignature: server=%s, client=%s "
               "(unset = not required)" % (server, client),
               "SMB messages are not required to be signed, so an attacker "
               "on the network can relay NTLM authentication to this host "
               "(e.g. viaResponder-style attacks) and tamper with file "
               "traffic. Enterprise and government baselines require "
               "signing on both ends.",
               "1. GPO: Computer Configuration\\Policies\\Windows Settings\\"
               "Security Settings\\Local Policies\\Security Options\\\n"
               "   'Microsoft network server: Digitally sign communications (always)' = Enabled\n"
               "   'Microsoft network client: Digitally sign communications (always)' = Enabled\n"
               "2. Or registry: Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\"
               "Services\\LanmanServer\\Parameters' RequireSecuritySignature 1\n"
               "3. Reboot or restart the LanmanServer service.")]


@register("WIN-028", "Application control policy (AppLocker / SRP)", WH)
def check_app_control(wctx):
    data = wctx.col("enterprise")
    if not data or "app_control" not in data:
        return [skipped_finding(check_app_control, "enterprise collector",
                                "Agent result has no 'enterprise' collector "
                                "- re-run the current agent (>= 1.2.0).")]
    ac = data.get("app_control") or {}
    rules = [str(r) for r in (ac.get("srpv2_rules") or [])]
    svc = str(ac.get("appidsvc") or "")
    if rules:
        return [secure_finding(check_app_control,
                               "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2",
                               "AppLocker rule collections: %s" % ", ".join(rules),
                               "Application allow-listing is configured.")]
    return [_f(check_app_control, "VULNERABLE", "LOW", 3.9,
               "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2 "
               "(missing) / AppIDSvc (%s)" % (svc or "not present"),
               "No AppLocker/SRP rule collections defined.",
               "Any executable a user can download or drop will run. Big "
               "corporate baselines (CIS, Microsoft Secure Workstation, "
               "DoD STIG) mandate application allow-listing on servers and "
               "high-risk workstations to stop malware execution outright.",
               "1. Define AppLocker policies via GPO: Computer Configuration\\"
               "Policies\\Windows Settings\\Security Settings\\Application "
               "Control Policies\\AppLocker.\n"
               "2. Start with audit-only rules (collect events), then enforce.\n"
               "3. Consider WDAC for stronger, kernel-level control.")]


@register("WIN-029", "RDP idle-session timeout", WH)
def check_rdp_timeout(wctx):
    data = wctx.col("enterprise")
    if not data or "rdp_timeout" not in data:
        return [skipped_finding(check_rdp_timeout, "enterprise collector",
                                "Agent result has no 'enterprise' collector "
                                "- re-run the current agent (>= 1.2.0).")]
    rd = data.get("rdp_timeout") or {}
    rdp_on = _as_int(rd.get("rdp_enabled")) == 0   # fDenyTSConnections 0 = enabled
    idle = _as_int(rd.get("max_idle_time_ms"))
    if not rdp_on:
        return [secure_finding(check_rdp_timeout,
                               "HKLM\\SYSTEM\\...\\Terminal Server",
                               "Remote Desktop is disabled on this host.",
                               "Idle timeout is not applicable when RDP is "
                               "disabled.")]
    if idle and idle > 0:
        mins = idle / 60000.0
        return [secure_finding(check_rdp_timeout,
                               "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\"
                               "Terminal Services:MaxIdleTime",
                               "MaxIdleTime = %d ms (%.0f min)" % (idle, mins),
                               "Unattended RDP sessions disconnect after "
                               "%.0f minutes." % mins)]
    return [_f(check_rdp_timeout, "VULNERABLE", "LOW", 3.4,
               "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal "
               "Services:MaxIdleTime",
               "RDP is enabled and no idle/disconnection limit is configured "
               "(MaxIdleTime unset).",
               "Unattended RDP sessions stay logged in forever - an "
               "unlocked console-equivalent session persists for anyone "
               "with physical or hijacked access. Corporate baselines "
               "disconnect idle sessions (typically 15-30 minutes).",
               "1. GPO: Computer Configuration\\Policies\\Administrative "
               "Templates\\Windows Components\\Remote Desktop Services\\\n"
               "   Remote Desktop Session Host\\Session Time Limits ->\n"
               "   'Set time limit for active but idle Remote Desktop Services sessions' = 15-30 min\n"
               "2. Or registry: Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\"
               "Microsoft\\Windows NT\\Terminal Services' MaxIdleTime 900000")]


# --------------------------------------------------------------------------- #
#  Runner
# --------------------------------------------------------------------------- #

CHECKS = [check_password_policy, check_lockout, check_guest, check_admin_account,
          check_admin_group, check_uac, check_lsa_ppl, check_ntlm, check_smb1,
          check_rdp, check_firewall, check_listeners, check_av_realtime,
          check_av_signatures, check_av_exclusions, check_bitlocker,
          check_patches, check_eol, check_wu_policy, check_service_paths,
          check_tls, check_autorun, check_screensaver, check_pslogging,
          check_auditpol, check_laps, check_smb_signing, check_app_control,
          check_rdp_timeout]


def run_all(wctx):
    """Run every WIN-xxx check against one agent result.

    Returns (findings, tests) - the same shapes the Linux audit produces,
    with Finding.host / test['host'] set to the Windows computer name.
    """
    findings, tests = [], []
    for fn in CHECKS:
        t0 = time.time()
        try:
            res = fn(wctx)
            if not isinstance(res, list) or not res:
                raise RuntimeError("check returned empty/invalid result")
        except Exception:
            res = [skipped_finding(fn, wctx.host,
                                   "Test crashed: %s"
                                   % traceback.format_exc(limit=1).strip())]
        dur_ms = int((time.time() - t0) * 1000)
        for f in res:
            f.host = wctx.host
        findings.extend(res)
        vulns = [f for f in res if f.status == "VULNERABLE"]
        if vulns:
            status = "VULNERABLE"
        elif any(f.status == "SECURE" for f in res):
            status = "SECURE"
        elif any(f.status == "INFO" for f in res):
            status = "INFO"
        else:
            status = "SKIPPED"
        locs = "; ".join(dict.fromkeys(f.location for f in res))[:300]
        tests.append({"check_id": fn.check_id, "name": fn.check_name,
                      "category": fn.check_category, "status": status,
                      "duration_ms": dur_ms, "locations": locs,
                      "findings": len(vulns), "host": wctx.host})
    return findings, tests
