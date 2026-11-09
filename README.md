<div align="center">

<img src="assets/hooky-icon.svg" alt="Hooky - Simple Cross-Platform Security Auditing" width="160">

# Hooky — Simple Cross-Platform Security Audit & Reporting Toolkit

**Read-only security auditing for Linux & Windows — with an interactive menu,
60 + 29 checks and HTML / PDF / JSON / CSV reports.**

`python3 hooky.py` · MIT License · Python 3.8+, stdlib only

</div>

---

**Hooky** is a read-only security auditor with a **zero-memorisation
interactive menu**. Run it, and it asks what you want to do:

```
$ python3 hooky.py
========================================================================
  Hooky 2.1.0 - Simple Cross-Platform Security Audit
========================================================================
  Local Linux: 60 tests   |   Windows: 29 tests   |   Reports: HTML + PDF + JSON + CSV
------------------------------------------------------------------------
  1) Audit this Linux system
  2) Audit a Windows system
  3) Receive results from Windows (webhook link - no SSH needed)
  4) Audit a saved Windows result file
  5) Show all security checks
  0) Exit
```

On **Linux** it runs **60 targeted tests** across six modules with plain
shell commands. **Windows hosts** are audited remotely through a bundled,
dependency-free **PowerShell agent** that the Linux controller can push over
SSH, receive through a **webhook link**, or import from a file. All findings
land in one timestamped report bundle that names every vulnerability, its
**exact location**, the **evidence found** and step-by-step **remediation**.

```
┌────────────────┐  SSH push / webhook link / manual import  ┌──────────────────────────┐
│  Windows host  │ ──( hooky-agent.ps1, read-only )──▶       │  Hooky (Linux controller) │
└────────────────┘                                           │  60 Linux + 29 WIN tests  │
┌────────────────┐                                           │  hooky_reports/           │
│  Linux host    │ ───────( local audit, 60 tests )──────▶   │  ├── …html  ← dashboard   │
└────────────────┘                                           │  ├── …pdf   ← mgmt report │
                                                             │  ├── …json  ← CI/SIEM     │
                                                             │  └── …csv   ← flat table  │
                                                             └───────────────────────────┘
```

## Requirements

- Python **3.8+** (standard library only) on the Linux controller.
- `reportlab` only for the PDF report (`pip install -r requirements.txt`).
- Linux (Debian/Ubuntu/RHEL-family tested). `find`, `grep`, `ss`,
  `dpkg-query`/`rpm` are used when present and degrade gracefully.
- Windows side needs **nothing installed** — only Windows PowerShell 5.1+
  (built into Win10/11/Server 2016+). SSH mode additionally needs Windows
  OpenSSH Server on the target.

## Quick start (menu — nothing to memorise)

```bash
python3 hooky.py
```

- **Option 1 — Audit this Linux system.** Runs all 60 tests, writes the
  report bundle, prints the report paths. Tip shown on screen: use
  `sudo python3 hooky.py scan` for full coverage.
- **Option 2 — Audit a Windows system.** Asks how to connect:
  - *Connect now over SSH* — asks for `user@host`, shows exactly what will
    happen (copy agent → run → fetch JSON → delete both), asks for your
    permission, then audits.
  - *Generate a webhook link* — prints a ready-made, one-line PowerShell
    command with the controller IP and a security token; run it on the
    Windows host (PowerShell as Administrator) and the result arrives here
    automatically and is audited with your confirmation.
- **Option 3 — Receive results from Windows** — the same webhook flow on
  its own (one collector, many hosts).
- **Option 4 — Audit a saved result file** — imports any agent JSON
  (received by webhook, copied manually, or from `examples/`).
- **Option 5 — Show all security checks.**

Every report file name and every webhook result carries a **timestamp**, so
runs never overwrite each other.

## Simple commands (all optional)

| Command | What it does |
| --- | --- |
| `python3 hooky.py` | interactive menu (in a terminal) |
| `python3 hooky.py scan` | audit **this** Linux system |
| `python3 hooky.py win admin@win-host` | audit a Windows host over SSH |
| `python3 hooky.py win` | Windows connection wizard (SSH or webhook) |
| `python3 hooky.py hook` | start the webhook collector, print the link |
| `python3 hooky.py get FILE` | audit a received Windows result file |
| `python3 hooky.py agent [FILE]` | export the Windows agent script |
| `python3 hooky.py checks` | show the full check catalogue |
| `python3 hooky.py help` | full help: every command + usage (-h / -help / --help too) |

Useful extras: `--quick` (shorter filesystem timeouts), `--modules
hardening,auth` (subset), `--formats html,json`, `--output-dir DIR`,
`--title TEXT`. All classic long options (`--all`, `--windows`,
`--windows-import`, `--hook …`) keep working for cron/CI. The old
`audit.py` and `vulnscope.py` names still run as compatibility wrappers.

**Exit codes:** `0` = clean, `1` = vulnerabilities found, `2` = tool error —
use as a CI gate: `python3 hooky.py scan || echo "baseline drift!"`.

## Audit modules & check catalogue

### System Hardening (HS-001 … HS-015)
SUID/SGID inventory & placement, world-writable SUID/SGID executables,
world-writable files/directories, unowned files, account database
permissions, IP forwarding, ICMP redirects, SYN cookies, source routing,
kernel pointer leaks, ASLR, SUID core dumps, password hashing, tmp-mount
hardening.

### Users & Authentication (AU-001 … AU-012)
UID-0 backdoors, empty password hashes, password aging, `pam_pwquality`
complexity, failed-login lockout, passwordless sudo (NOPASSWD), system
accounts with shells, duplicate UID/GID, PATH hygiene, legacy trust files,
root `authorized_keys`, user inventory.

### Network Exposure (NW-001 … NW-009)
Risky/legacy listeners, world-exposed binds, host firewall state, sshd root
login & auth hardening, weak ciphers/MACs/Kex, legacy cleartext packages,
permissive NFS exports, promiscuous interfaces.

### Packages & Known CVEs (PK-001 … PK-007)
OS end-of-life detection, pending security updates, reboot required, known-CVE
offline signature matching (sudo, polkit, OpenSSH, curl, bash, zlib, glibc,
log4j), unattended-upgrades, dev toolchain, obsolete kernels.

### Secrets & Credentials (SC-001 … SC-009)
SSH private-key permissions, secrets in shell history, world-readable key
files, hardcoded secrets in configs, exposed web `.env` files, Docker socket
exposure, cron file security, GRUB password, auth-log permissions.

### Enterprise & Compliance (EC-001 … EC-008) — the controls corporations are audited against
- **EC-001** Audit framework (auditd) installed *and* running — PCI DSS Req. 10, ISO 27001 A.8.15, CIS 4.1
- **EC-002** Time synchronisation (chrony/NTP) — log correlation, Kerberos
- **EC-003** Central log shipping to a SIEM/log host
- **EC-004** Legal warning banner (`/etc/issue.net`)
- **EC-005** Password aging policy (`PASS_MAX_DAYS` ≤ 90)
- **EC-006** sudo command logging (`Defaults logfile=`)
- **EC-007** Core dump restriction (`fs.suid_dumpable = 0`)
- **EC-008** USB mass-storage driver blocked (data-exfiltration control)

### Windows Systems (WIN-001 … WIN-029) — against agent results
Accounts: password & lockout policy, Guest/built-in Administrator, admin
group inventory. Hardening: UAC, LSA RunAsPPL, NTLM level, SMBv1, BitLocker,
service-path privesc risks, SCHANNEL TLS/SSL, AutoRun, screen lock,
PowerShell logging, **LAPS (WIN-026)**, **SMB signing (WIN-027)**,
**AppLocker/SRP (WIN-028)**, **RDP idle timeout (WIN-029)**. Network: RDP &
NLA, firewall profiles, risky listeners. Updates & AV: Defender protection,
signature age, dangerous exclusions, patch freshness & pending reboot, OS
end-of-life, automatic-update policy, `auditpol` coverage.

## Auditing Windows hosts — three ways, one report

### A. SSH push (fully automated)
One-time prep on the Windows host (elevated PowerShell):
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic; Start-Service sshd
```
Set up key auth (administrators: `C:\ProgramData\ssh\administrators_authorized_keys`).
Then from the Linux controller:
```bash
python3 hooky.py win administrator@winsrv01        # wizard / direct
# menu equivalent: option 2 → "Connect now over SSH"
```
Hooky scp's the agent over, runs it, pulls the JSON back, runs the 29
WIN checks and deletes both files from the host.

### B. Webhook link (no SSH — agents send results to you)
```bash
python3 hooky.py hook            # or menu option 3
```
The tool prints a ready-to-paste command (with your controller IP + token):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File hooky-agent.ps1 ^
    -Uri http://<controller-ip>:8090/hook -Token '<token>'
```
Each arriving result is saved timestamped in `hooky_results/`, and the
menu flow offers to audit it **immediately** with one keypress. The webhook
endpoint requires the shared token (`X-Hooky-Token` header).

### C. Manual / offline
```bash
python3 hooky.py agent                     # export the agent script
# copy it to Windows, run (elevated):
#   powershell -NoProfile -ExecutionPolicy Bypass -File hooky-agent.ps1
python3 hooky.py get hooky-agent-output.json
```

Try it right now without a real server:
```bash
python3 hooky.py get examples/windows-demo-result.json
```
(a synthetic Windows Server 2022 with planted vulnerabilities — 46 findings).

### Agent reference
| Agent parameter | Meaning |
| --- | --- |
| `-OutFile PATH` | JSON result path (default `./hooky-agent-output.json`) |
| `-Uri URL` | also POST the JSON to the Hooky webhook |
| `-Token T` | sent as `X-Hooky-Token` header with `-Uri` |
| exit 0 / 2 / 3 | success / cannot write file / push failed |

The agent is read-only, installs nothing, and collects 14 snapshots
(system, `net accounts`, local users/groups, registry hardening keys,
Defender, third-party AV, firewall, BitLocker, hotfixes, `auditpol`,
listeners, services, shares, enterprise controls). Non-English Windows:
`net accounts` / `auditpol` parsers expect English output and mark affected
tests `SKIPPED` otherwise.

## Report contents (every format)

1. **System identification** — hostname/FQDN, platform, OS, kernel/build,
   IP, CPU/RAM, uptime, audit date-time, executing user & privilege level,
   tool version.
2. **Audit statistics** — tests conducted, vulnerable / passed / skipped,
   findings by severity, overall risk rating.
3. **Vulnerability details** — for each finding: test ID & name, severity +
   0–10 score, **exact location** (`file:line`, port, registry key,
   parameter), **evidence excerpt**, why it matters, and numbered
   **remediation steps** with concrete commands.
4. **Full test log** — every test with result, **host** (local or Windows
   computer name), locations examined, per-test duration.
5. **Method, scope & limitations** statement.

The **HTML** report adds interactive severity/category filters, free-text
search, copy-to-clipboard for locations and fixes, and collapsible evidence.
The **JSON/CSV** payloads carry the same data for SIEM pipelines and Excel.

## Scheduled audits

```cron
# weekly full audit, Monday 06:00
0 6 * * 1  cd /opt/hooky && sudo python3 hooky.py scan --output-dir /var/log/hooky/$(date +\%G-\%V) >> /var/log/hooky/cron.log 2>&1
# webhook collector for Windows fleet (systemd service or tmux)
```

## Limitations & notes

- **Offline CVE signatures (snapshot 2026-11):** vendors often backport
  fixes without bumping versions, so version matching can flag patched
  packages — PK-004 findings carry this caveat inline.
- **Unprivileged runs** cannot read `/etc/shadow`, `/etc/sudoers`, firewall
  state etc.; those tests are marked `SKIPPED` with the reason — re-run with
  `sudo`.
- **Containers:** kernel sysctls, GRUB and service-level checks reflect the
  *host*; EC findings are annotated accordingly.
- **Authorisation:** only audit systems you own or are authorised to assess.
  Hooky is read-only and safe for production.

## License

[MIT](LICENSE) — free to use, modify and distribute; provided "as is" with no
warranty. Only audit systems you own or are explicitly authorised to test.

## Project layout

```
hooky/
├── hooky.py               # CLI entry point: menu + scan/win/hook/get/agent/checks
├── audit.py               # compatibility wrapper for the old entry name
├── vulnscope.py           # compatibility wrapper for the original name
├── windows/
│   └── hooky-agent.ps1    # read-only PowerShell agent (v1.3.0)
├── examples/
│   └── windows-demo-result.json  # synthetic vulnerable Windows 2022 fixture
├── lib/
│   ├── core.py            # Finding model, safe helpers, vercmp, metadata
│   ├── checks_hardening.py    # HS-001…HS-015
│   ├── checks_auth.py         # AU-001…AU-012
│   ├── checks_network.py      # NW-001…NW-009
│   ├── checks_packages.py     # PK-001…PK-007 (+ offline CVE DB)
│   ├── checks_secrets.py      # SC-001…SC-009
│   ├── checks_enterprise.py   # EC-001…EC-008 (corporate compliance)
│   ├── checks_windows.py      # WIN-001…WIN-029 (analyse agent JSON)
│   ├── remote.py              # SSH push transport + webhook collector
│   ├── report_data.py         # JSON + CSV writers
│   ├── report_html.py         # self-contained interactive HTML dashboard
│   └── report_pdf.py          # formal PDF report (ReportLab)
├── requirements.txt
├── LICENSE                 # MIT
├── README.md
└── assets/
    └── hooky-icon.svg       # project icon
```

Extending Hooky with your own check is one function:

```python
from .core import register, Finding

@register("EC-900", "My custom control", "Enterprise & Compliance")
def check_custom(ctx):
    if problem:
        return [Finding("EC-900", "My custom control", "Enterprise & Compliance",
                        "VULNERABLE", "MEDIUM", 5.0, "/exact/path:line",
                        "evidence", "why it matters", "how to fix")]
    return [Finding("EC-900", "My custom control", "Enterprise & Compliance",
                    "SECURE", "INFO", 0.0, "/exact/path", "ok", "verified", "")]
```

Add it to that module's `CHECKS` list — it automatically appears in the
menu counts, every report format and the test log.
