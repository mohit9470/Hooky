<div align="center">

<img src="assets/banner.png" alt="Hooky - Simple Cross-Platform Security Auditing" width="640">

# Hooky — Simple Cross-Platform Security Audit & Reporting Toolkit

**Read-only security auditing for Linux & Windows — with an interactive menu,
60 + 29 checks and HTML / PDF / JSON / CSV reports.**

`python3 hooky.py` · MIT License · Python 3.8+, stdlib only

</div>

---

**Contents**

1. [What is Hooky?](#what-is-hooky)
2. [What's new](#whats-new)
3. [Requirements](#requirements)
4. [Installation — step by step](#installation--step-by-step)
5. [Quick start (menu — nothing to memorise)](#quick-start-menu--nothing-to-memorise)
6. [Commands & options](#commands--options)
7. [Audit modules & check catalogue](#audit-modules--check-catalogue)
8. [Auditing Windows hosts — four ways, one report](#auditing-windows-hosts--four-ways-one-report)
9. [Troubleshooting & FAQ](#troubleshooting--faq)
10. [Report contents (every format)](#report-contents-every-format)
11. [Scheduled audits](#scheduled-audits)
12. [Limitations & notes](#limitations--notes)
13. [License](#license)
14. [Project layout](#project-layout)
15. [Extending Hooky](#extending-hooky)

## What is Hooky?

**Hooky** is a read-only security auditor with a **zero-memorisation
interactive menu**. Run it, and it asks what you want to do:

```
$ python3 hooky.py
========================================================================
  Hooky 2.3.0 - Simple Cross-Platform Security Audit
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
dependency-free **PowerShell agent** (v1.4.0 — collectors run **in
parallel**, a full scan usually takes **15–30 seconds**; `-Quick` gives a
~10-second triage) that the Linux controller can push over SSH, receive
through a **webhook**, audit with a **one-click link** the user simply
opens, or import from a file. All findings
land in one timestamped report bundle that names every vulnerability, its
**exact location**, the **evidence found** and step-by-step **remediation**.

```
┌────────────────┐  SSH push / webhook / one-click link / import ┌─────────────────────────┐
│  Windows host  │ ──( hooky-agent.ps1, read-only )──▶          │  Hooky (Linux controller) │
└────────────────┘                                              │  60 Linux + 29 WIN tests  │
┌────────────────┐                                              │  hooky_reports/           │
│  Linux host    │ ───────( local audit, 60 tests )──────▶      │  ├── …html  ← dashboard   │
└────────────────┘                                              │  ├── …pdf   ← mgmt report │
                                                                │  ├── …json  ← CI/SIEM     │
                                                                │  └── …csv   ← flat table  │
                                                                └───────────────────────────┘
```

## What's new

| Version | Highlights |
| --- | --- |
| **2.3.0** (current) | **One-click audit link** — print a web link, the Windows user clicks *I allow*, opens one downloaded file, clicks *Yes*; the audit runs, reports are generated automatically and the link burns itself after a single use. New `link` command + menu option. |
| **2.2.0** | **PowerShell agent v1.4.0** — the 14 collectors now run **in parallel** (full scan ~15–30 s instead of minutes), plus a `-Quick` triage mode (~10 s). |
| **2.1.0** | Renamed to **Hooky**; simplified command surface (`scan` / `win` / `hook` / `get` / `agent`). |
| **2.0.0** | SecureAudit rewrite: strict read-only guarantee, unified timestamped report bundle (HTML + PDF + JSON + CSV). |
| 1.x | Original **VulnScope** CLI. |

## Requirements

- Python **3.8+** (standard library only) on the Linux controller.
- `reportlab` **only for the PDF report** (`pip install -r requirements.txt`).
  HTML, JSON and CSV work with zero extra packages.
- Linux (Debian/Ubuntu/RHEL-family tested). `find`, `grep`, `ss`,
  `dpkg-query`/`rpm` are used when present and degrade gracefully.
- **Windows side needs nothing installed** — only Windows PowerShell 5.1+
  (built into Win10/11/Server 2016+). SSH mode additionally needs Windows
  OpenSSH Server on the target.

## Installation — step by step

Everything runs on the **Linux controller**; the Windows side installs
nothing (see the box at the end of this section).

### Step 1 — Get Hooky onto the Linux controller

Copy the `hooky/` folder to the machine that will run the audits, e.g.
`/opt/hooky`:

```bash
# option A: from the release zip
sudo unzip hooky-2.3.0.zip -d /opt
# option B: from another machine
scp -r hooky/ user@controller:/tmp/ && sudo mv /tmp/hooky /opt/hooky
```

Then enter the folder — all commands below are run from there:

```bash
cd /opt/hooky
```

### Step 2 — Check Python

```bash
python3 --version        # must print 3.8 or newer
```

If it is missing: `sudo apt install python3` (Debian/Ubuntu/Kali) or
`sudo dnf install python3` (RHEL/Fedora).

### Step 3 — Create a virtual environment (recommended)

A venv keeps Hooky's only dependency isolated from the system Python —
this also avoids the PEP 668 "externally-managed-environment" error on
Kali / Debian 12+ / Ubuntu 23.04+:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

(If venv creation fails: `sudo apt install python3-venv`, then retry.)
Activate the venv in every new shell before running Hooky — or skip the
venv and use the `--break-system-packages` fallback shown in Step 4.

### Step 4 — Install the PDF dependency

HTML, JSON and CSV reports need **no** installation at all. For PDF:

```bash
pip install -r requirements.txt      # installs reportlab
```

> **Kali Linux / Debian 12+ / Ubuntu 23.04+** — if pip refuses with
> `error: externally-managed-environment`, either use the venv from
> Step 3 (recommended) or install system-wide with:
> `pip3 install --break-system-packages reportlab`

No reportlab? Everything else still works — Hooky simply notes that PDF
is unavailable and offers the other formats.

### Step 5 — Verify the installation

```bash
python3 hooky.py --version    # → "Hooky 2.3.0"
python3 hooky.py checks       # → the full catalogue (89 checks: 60 HS/AU/NW/PK/SC/EC + 29 WIN)
```

Then try a **real audit without a real server** — Hooky ships a synthetic,
vulnerable Windows Server 2022 fixture:

```bash
python3 hooky.py get examples/windows-demo-result.json
```

Expected: 28 of 29 tests vulnerable, **46 findings** (7 CRITICAL), risk
rating CRITICAL, and a timestamped report bundle written to
`hooky_reports/`. Exit code is `1` (vulnerabilities found) — that is the
correct, intended result for this planted-vulnerability demo.

### Step 6 — First real audit

```bash
python3 hooky.py                       # menu — pick 1
# or directly:
sudo python3 hooky.py scan             # full coverage (shadow, sudoers, firewall, …)
```

Without `sudo` the tool still runs, but tests it cannot read are marked
`SKIPPED` with the reason instead of silently passing. Reports land in
`./hooky_reports/` (change with `--output-dir DIR`).

### Step 7 — (Optional) receive Windows results — open the port

Only needed for the **webhook** and **one-click link** channels, which
listen on TCP **8090** by default:

```bash
sudo ufw allow 8090/tcp                # Ubuntu/Debian
# or: sudo firewall-cmd --add-port=8090/tcp --permanent && sudo firewall-cmd --reload
```

SSH mode (channel A) needs only normal SSH access. The one-click link
works from any device that can reach the controller (LAN/VPN).

### Step 8 — (Optional) make Hooky handy & persistent

```bash
# run from anywhere
sudo ln -s /opt/hooky/hooky.py /usr/local/bin/hooky
```

Weekly cron audit:

```cron
0 6 * * 1  cd /opt/hooky && sudo python3 hooky.py scan --output-dir /var/log/hooky/$(date +\%G-\%V) >> /var/log/hooky/cron.log 2>&1
```

To keep the webhook collector alive after reboots (example systemd unit,
`/etc/systemd/system/hooky-hook.service`):

```ini
[Unit]
Description=Hooky webhook collector
After=network-online.target

[Service]
WorkingDirectory=/opt/hooky
ExecStart=/usr/bin/python3 hooky.py hook
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then: `sudo systemctl enable --now hooky-hook`.

> **Windows side: nothing to install.** The agent is fetched/created at
> run time — pushed by Hooky over SSH (channel A), generated as a
> ready-made one-line command (channel B), downloaded as a single
> `hooky-audit.cmd` from the one-click link (channel C), or exported with
> `python3 hooky.py agent` and copied over (channel D). Only SSH mode
> needs one-time prep on the target (OpenSSH Server — see channel A).

### Installation checklist

| Check | Expected result |
| --- | --- |
| `python3 hooky.py --version` | `Hooky 2.3.0` |
| `python3 hooky.py checks` | 89 checks listed (60 Linux + 29 Windows) |
| `python3 hooky.py get examples/windows-demo-result.json` | 46 findings, reports in `hooky_reports/` |
| `python3 hooky.py scan --quick` | local Linux audit completes, exit code 0 or 1 |
| `python3 hooky.py hook` | prints webhook command + link, waits on port 8090 |

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
  - *Webhook + agent command* — prints a ready-made, one-line PowerShell
    command with the controller IP and a security token; run it on the
    Windows host (PowerShell as Administrator) and the result arrives here
    automatically and is audited with your confirmation.
  - *One-click audit link* — the easiest way: Hooky prints a web link, you
    send it to the Windows user, they click **I allow**, open the downloaded
    file, click **Yes** — and the report appears on your side automatically
    (see channel C below).
- **Option 3 — Receive results from Windows** — the same webhook flow on
  its own (one collector, many hosts).
- **Option 4 — Audit a saved result file** — imports any agent JSON
  (received by webhook, copied manually, or from `examples/`).
- **Option 5 — Show all security checks.**

After every audit the menu asks **which report format** you want:

```
  Which report format do you want?
    1) HTML   interactive dashboard - recommended, opens in any browser
    2) PDF    formal document (needs reportlab:  pip install reportlab)
    3) JSON   raw machine-readable data for other tools
    4) CSV    spreadsheet - opens in Excel / LibreOffice
    5) ALL    every format (HTML + PDF + JSON + CSV)
  Press Enter = 5 (all formats)
```

Every report file name and every webhook result carries a **timestamp**, so
runs never overwrite each other.

## Commands & options

| Command | What it does |
| --- | --- |
| `python3 hooky.py` | interactive menu (in a terminal) |
| `python3 hooky.py scan` | audit **this** Linux system |
| `python3 hooky.py win admin@win-host` | audit a Windows host over SSH |
| `python3 hooky.py win` | Windows connection wizard (SSH, webhook or link) |
| `python3 hooky.py hook` | start the webhook collector, print the command |
| `python3 hooky.py link` | one-click audit: generate the link, send it, done |
| `python3 hooky.py get FILE` | audit a received Windows result file |
| `python3 hooky.py agent [FILE]` | export the Windows agent script |
| `python3 hooky.py checks` | show the full check catalogue |
| `python3 hooky.py help` | full help: every command + usage (`-h` / `-help` / `--help` too) |

Useful extras: `--quick` (shorter filesystem timeouts), `--modules
hardening,auth` (subset), `--formats html,json`, `--output-dir DIR`,
`--title TEXT`, `--hook-port PORT`, `--hook-token TOKEN`, `--hook-dir DIR`,
`-V/--version`. All classic long options (`--all`, `--windows`,
`--windows-import`, `--export-agent`, `--hook …`) keep working for
cron/CI. The old `audit.py` and `vulnscope.py` names still run as
compatibility wrappers.

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

## Auditing Windows hosts — four ways, one report

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

### C. One-click audit link (no SSH, no commands on the Windows side)
```bash
python3 hooky.py link            # or menu option 2 → "One-click audit link"
```
Hooky prints a **one-time link** like `http://<controller-ip>:8090/go/hooky-…`
(valid **30 minutes** by default, **one audit only**). Send it to the person
whose PC you want to audit — chat, e-mail, any way you like. Then everything
runs by itself:

1. they open the link → a **consent page** explains what will be collected
   (read-only: nothing installed, nothing changed) with *I allow* / *Decline*;
2. *I allow* downloads **one self-contained file** (`hooky-audit.cmd`) with
   the whole read-only agent embedded;
3. they open it and click **Yes** on the native Windows permission popup;
4. the audit runs (~15–30 s), the result is sent back **once**;
5. Hooky generates the reports **automatically**, closes the link (the token
   is burned — a second submission is rejected with 403) and exits by itself.

While waiting you see live status lines: *user opened the link*, *user
allowed*, *file downloaded*, *result received*. Declining burns the link too
and collects nothing.

Notes: the link works from any device that can reach the controller on the
network (same LAN/VPN — for true internet-wide access you would need port
forwarding or a tunnel, which is not recommended for beginners). A browser
can never execute scripts directly — the download + open step is mandatory
Windows/browser security behaviour, which is exactly why the second consent
popup exists.

### D. Manual / offline
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
| `-Quick` | fast triage mode (~10 s, reduced timeouts) |
| exit 0 / 2 / 3 | success / cannot write file / push failed |

The agent is read-only, installs nothing, and collects 14 snapshots
(system, `net accounts`, local users/groups, registry hardening keys,
Defender, third-party AV, firewall, BitLocker, hotfixes, `auditpol`,
listeners, services, shares, enterprise controls). Non-English Windows:
`net accounts` / `auditpol` parsers expect English output and mark affected
tests `SKIPPED` otherwise.

## Troubleshooting & FAQ

**I opened the webhook URL in my browser and got `{"error": "use POST /hook"}`.**
That is expected. Browsers send GET; the endpoint only accepts **POST with
the token header**. The printed command is meant to run in **PowerShell on
the Windows host**, not in a browser.

**The agent printed "push failed" and exited (exit 3).** The agent makes no
automatic retries; the local result file is kept. Work through its 4-point
checklist and run the same command again — results are timestamped, so
nothing is overwritten:
1. Linux IP and port correct in `-Uri`? (`hostname -I` on the controller)
2. Is the collector still running there? (`python3 hooky.py hook`)
3. Does `-Token` match the collector's token?
4. Any firewall between the two machines? (`sudo ufw allow 8090/tcp`)

**`403 invalid or missing X-Hooky-Token`.** Token mismatch — copy the
command exactly as printed by `hook` (or pass the same token with
`--hook-token`).

**One-click link: `403 invalid or expired audit link token` / "gone" page.**
The link has a **30-minute TTL**, works **once**, and is burned on success
*and* on decline. Generate a fresh one: `python3 hooky.py link`.

**The Windows user ran `hooky-audit.cmd` but I never got the result.**
The link is only burned after a **successful** delivery — if the network or
the controller was down, the downloaded file can simply be **run again**.
If the result arrived but report generation failed (HTTP 500), the link
stays open for the same reason: run the file again.

**Nothing arrives even though the agent says it pushed.** Check the
collector's terminal for `REJECTED` / `ACCEPTED` lines, confirm both
machines are on the same network/VPN, and open TCP 8090 on the controller
(Step 7 of the installation).

**PDF report fails / says reportlab is missing.** Install it (Step 4):
`pip install -r requirements.txt`. HTML/JSON/CSV never need it.

**Many Linux tests are `SKIPPED`.** Unprivileged run — re-run with `sudo`
for full coverage. Every skip states its reason in the report.

**Windows tests show `SKIPPED` on a non-English Windows.** `net accounts`
and `auditpol` output is language-dependent; the parsers expect English and
skip cleanly otherwise.

**`error: externally-managed-environment` when pip installing.** Kali /
Debian 12+ / Ubuntu 23.04+ protect the system Python — use the venv
(Step 3) or `pip3 install --break-system-packages reportlab` (Step 4).

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
# webhook collector for the Windows fleet: keep it running with the
# systemd unit from Installation Step 8 (or tmux / screen)
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
- **One-click link reach:** the link is reachable from the controller's
  LAN/VPN; internet-wide use needs port forwarding or a tunnel (not
  recommended — expose only what you must).
- **Authorisation:** only audit systems you own or are authorised to assess.
  Hooky is read-only and safe for production.

## License

[MIT](LICENSE) — free to use, modify and distribute; provided "as is" with no
warranty. Only audit systems you own or are explicitly authorised to test.

## Project layout

```
hooky/
├── hooky.py               # CLI entry point: menu + scan/win/hook/link/get/agent/checks
├── audit.py               # compatibility wrapper for the old entry name
├── vulnscope.py           # compatibility wrapper for the original name
├── windows/
│   └── hooky-agent.ps1    # read-only PowerShell agent (v1.4.0, parallel)
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
│   ├── remote.py              # SSH push transport + webhook/link collector
│   ├── link.py                # one-click link: consent pages + .cmd payload
│   ├── report_data.py         # JSON + CSV writers
│   ├── report_html.py         # self-contained interactive HTML dashboard
│   └── report_pdf.py          # formal PDF report (ReportLab)
├── requirements.txt
├── LICENSE                 # MIT
├── README.md
└── assets/
    ├── logo.png            # square icon (avatar / favicon / social preview)
    └── banner.png          # wide README banner
```

## Extending Hooky

Adding your own check is one function:

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
