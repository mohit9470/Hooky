#!/usr/bin/env python3
"""Hooky - self-contained interactive HTML report generator.

The output is a single file with inline CSS/JS, no external dependencies,
renderable offline in any modern browser.
"""

import html as _html
import re
from .core import SEVERITY_ORDER, TOOL_NAME, TOOL_VERSION, SEV_SCORE_BANDS

SEV_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
    "LOW": "#2563eb", "INFO": "#64748b", "SECURE": "#16a34a",
    "SKIPPED": "#94a3b8",
}

_CSS = """
:root{--bg:#0f172a;--panel:#1e293b;--panel2:#16213a;--line:#334155;--fg:#e2e8f0;
--mut:#94a3b8;--acc:#38bdf8;--crit:#dc2626;--high:#ea580c;--med:#d97706;
--low:#2563eb;--info:#64748b;--ok:#16a34a;--skip:#94a3b8}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,BlinkMacSystemFont,
'Segoe UI',Roboto,'Noto Sans',sans-serif;padding-bottom:60px}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px}
header{background:linear-gradient(135deg,#0b1220 0%,#152238 60%,#1a2c49 100%);
border-bottom:1px solid var(--line);padding:26px 0 22px;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:14px}
.brand .logo{width:44px;height:44px;flex:0 0 44px}
h1{font-size:22px;font-weight:700;letter-spacing:.3px}
.sub{color:var(--mut);font-size:13px;margin-top:2px}
.banner{margin:18px 0 4px;padding:13px 18px;border-radius:10px;font-weight:700;
font-size:16px;letter-spacing:.4px;display:flex;justify-content:space-between;align-items:center}
.banner.bad{background:rgba(220,38,38,.12);border:1px solid rgba(220,38,38,.55);color:#fca5a5}
.banner.good{background:rgba(22,163,74,.12);border:1px solid rgba(22,163,74,.55);color:#86efac}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(255px,1fr));gap:12px;margin:16px 0 22px}
.meta .cell{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.meta .k{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.8px}
.meta .v{font-size:13.5px;margin-top:3px;word-break:break-word}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;text-align:center}
.card .n{font-size:26px;font-weight:800}
.card .l{color:var(--mut);font-size:11.5px;text-transform:uppercase;letter-spacing:.8px;margin-top:2px}
.c-crit .n{color:var(--crit)}.c-high .n{color:var(--high)}.c-med .n{color:var(--med)}
.c-low .n{color:var(--low)}.c-vuln .n{color:#f87171}.c-ok .n{color:var(--ok)}
.c-all .n{color:var(--acc)}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:6px 0 16px}
.sev-btn{background:var(--panel);border:1px solid var(--line);color:var(--fg);
padding:7px 14px;border-radius:999px;cursor:pointer;font-size:12.5px;font-weight:600}
.sev-btn.active{background:var(--acc);border-color:var(--acc);color:#082f49}
.sev-btn .cnt{opacity:.75;font-weight:400;margin-left:4px}
.toolbar input,.toolbar select{background:var(--panel);border:1px solid var(--line);
color:var(--fg);border-radius:8px;padding:7px 12px;font-size:13px;outline:none}
.toolbar input{flex:1;min-width:200px}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:5px;
border-radius:12px;padding:16px 18px;margin-bottom:14px}
.finding .top{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px}
.chip{font-size:10.5px;font-weight:800;letter-spacing:.8px;padding:3px 10px;border-radius:999px;color:#fff}
.chip.vuln{background:var(--crit)}
.finding h3{font-size:15.5px;font-weight:700;flex:1;min-width:200px}
.fid{color:var(--mut);font-weight:600;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.row{margin:10px 0}
.row .lab{font-size:10.5px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);
margin-bottom:4px;display:flex;justify-content:space-between;align-items:center}
pre{background:#0b1220;border:1px solid var(--line);border-radius:8px;padding:10px 12px;
font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;color:#cbd5e1;white-space:pre-wrap;
word-break:break-word;max-height:260px;overflow:auto}
.desc{font-size:13.5px;color:#cbd5e1}
.remediation{background:rgba(22,163,74,.07);border:1px solid rgba(22,163,74,.4);
border-radius:8px;padding:10px 14px}
.remediation ol{margin:6px 0 0 18px}
.remediation li{margin:4px 0;font-size:13px}
.copy{background:none;border:1px solid var(--line);color:var(--mut);border-radius:6px;
font-size:10.5px;padding:2px 8px;cursor:pointer}
.copy:hover{color:var(--fg);border-color:var(--mut)}
.loc{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:#7dd3fc;
word-break:break-all}
h2{font-size:18px;margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;overflow:hidden;
font-size:12.5px}
th{background:var(--panel2);color:var(--mut);text-align:left;font-size:10.5px;
text-transform:uppercase;letter-spacing:.8px;padding:9px 10px;border-bottom:1px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid rgba(51,65,85,.5);vertical-align:top}
tr:last-child td{border-bottom:none}
td.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#94a3b8;word-break:break-all}
.st{font-weight:800;font-size:10.5px;letter-spacing:.6px;padding:2px 8px;border-radius:6px;color:#fff;white-space:nowrap}
.st-VULNERABLE{background:var(--crit)}.st-SECURE{background:var(--ok)}
.st-INFO{background:var(--info)}.st-SKIPPED{background:#475569}
footer{margin-top:40px;color:#64748b;font-size:11.5px;border-top:1px solid var(--line);padding-top:14px}
.hosttag{font-size:10.5px;font-weight:800;color:#a5b4fc;border:1px solid rgba(99,102,241,.55);
background:rgba(79,70,229,.16);padding:3px 9px;border-radius:999px;letter-spacing:.5px;white-space:nowrap}
.hidden{display:none}
"""

_JS = """
function setSev(btn, sev){
  document.querySelectorAll('.sev-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active'); apply();
}
function apply(){
  var q=(document.getElementById('q').value||'').toLowerCase();
  var cat=document.getElementById('cat').value;
  document.querySelectorAll('.finding').forEach(function(f){
    var okS=f.dataset.sev===window.sev||window.sev==='ALL';
    var okC=cat==='ALL'||f.dataset.cat===cat;
    var okQ=!q||f.dataset.text.indexOf(q)>=0;
    f.classList.toggle('hidden', !(okS&&okC&&okQ));
  });
}
window.sev='ALL';
document.querySelectorAll('.sev-btn').forEach(function(b){
  b.addEventListener('click',function(){setSev(b,b.dataset.sev);window.sev=b.dataset.sev;apply();});
});
document.getElementById('q').addEventListener('input',apply);
document.getElementById('cat').addEventListener('change',apply);
document.getElementById('toggleAll').addEventListener('click',function(){
  var c=document.getElementById('findings');
  c.classList.toggle('compact');
  var hidden=c.classList.contains('compact');
  c.querySelectorAll('.finding .body').forEach(function(x){x.classList.toggle('hidden',hidden);});
  this.textContent=hidden?'Expand all evidence':'Collapse all evidence';
});
document.addEventListener('click',function(e){
  var t=e.target.closest('[data-copy]');if(!t)return;
  var src=document.getElementById(t.dataset.copy);
  var txt=src?src.innerText:'';
  function done(){t.textContent='Copied!';setTimeout(function(){t.textContent='Copy';},1200);}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done);}
  else{var ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);
    ta.select();try{document.execCommand('copy');done();}catch(err){}document.body.removeChild(ta);}
});
"""

_SHIELD = (
    '<svg class="logo" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<path d="M24 4L6 11v12c0 10.5 7.2 17.9 18 21 10.8-3.1 18-10.5 18-21V11L24 4z" '
    'fill="#12253f" stroke="#38bdf8" stroke-width="2.4"/>'
    '<path d="M15 24.5l6.5 6.5L34 18" stroke="#38bdf8" stroke-width="3.2" '
    'stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>'
)


def esc(t):
    return _html.escape(str(t or ""))


def _chip(status):
    return '<span class="st st-%s">%s</span>' % (esc(status), esc(status))


def _sev_chip(sev, score):
    color = SEV_COLORS.get(sev, "#64748b")
    return ('<span class="chip" style="background:%s">%s &middot; %.1f/10</span>'
            % (color, esc(sev), score))


def generate_html(md, summary, findings, tests, path, title):
    host = md.get("fqdn") or md.get("hostname")
    targets = md.get("remote_targets") or []
    if md.get("no_local") and targets:
        host = targets[0].get("computer") or host
    vulns = [f for f in findings if f.status == "VULNERABLE"]
    vulns.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.score))
    sev_counts = summary["by_severity"]

    cards = [
        ("c-all", summary["total_tests"], "Tests conducted"),
        ("c-vuln", summary["tests_vulnerable"], "Vulnerable tests"),
        ("c-crit", sev_counts["CRITICAL"], "Critical"),
        ("c-high", sev_counts["HIGH"], "High"),
        ("c-med", sev_counts["MEDIUM"], "Medium"),
        ("c-low", sev_counts["LOW"], "Low"),
        ("c-ok", summary["tests_secure"], "Passed"),
        ("", summary["tests_skipped"], "Skipped"),
    ]
    cards_html = "".join(
        '<div class="card %s"><div class="n">%s</div><div class="l">%s</div></div>'
        % (cls, n, l) for cls, n, l in cards)

    if vulns:
        banner = ('<div class="banner bad"><span>%d VULNERABILITIES FOUND - '
                  'RISK RATING: %s</span><span>highest: %s</span></div>'
                  % (len(vulns), summary["risk_rating"],
                     vulns[0].severity if vulns else "-"))
    else:
        banner = ('<div class="banner good"><span>NO VULNERABILITIES DETECTED IN '
                  'EXECUTED TESTS</span><span>%d test(s) skipped</span></div>'
                  % summary["tests_skipped"])

    meta_cells = [
        ("System name", md.get("fqdn") or md.get("hostname")),
        ("Hardware / platform", md.get("hardware_model")),
        ("Virtualisation", md.get("virtualization")),
        ("Machine ID", md.get("machine_id")),
        ("Operating system", md.get("os")),
        ("Kernel / architecture", "%s / %s" % (md.get("kernel"), md.get("arch"))),
        ("Primary IP address", md.get("ip")),
        ("CPU", "%s x%d" % (md.get("cpu"), md.get("cpu_count") or 1)),
        ("Memory", md.get("memory")),
        ("Uptime", md.get("uptime")),
        ("Audit date", md.get("audit_time")),
        (("Audited Windows targets", " | ".join(
            "%s (%s): %d finding(s)"
            % (t.get("computer"), t.get("os"), t.get("findings", 0))
            for t in targets)) if targets else ("Audit scope", "local Linux host")),
        ("Run as", "%s (%s)" % (md.get("user"),
                                "root - full audit" if md.get("privileged")
                                else "unprivileged - reduced coverage")),
        ("Scanned by", md.get("tool")),
        ("Audit title", title),
    ]
    meta_html = "".join(
        '<div class="cell"><div class="k">%s</div><div class="v">%s</div></div>'
        % (esc(k), esc(v)) for k, v in meta_cells)

    # severity filter buttons
    btns = [("ALL", summary["total_tests"])]
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        btns.append((s, sev_counts[s]))
    btn_html = "".join(
        '<button class="sev-btn %s" data-sev="%s">%s<span class="cnt">%d</span></button>'
        % ("active" if s == "ALL" else "", s, s.title(), n) for s, n in btns)

    categories = sorted({f.category for f in vulns})
    cat_opts = '<option value="ALL">All categories</option>' + "".join(
        '<option value="%s">%s</option>' % (esc(c), esc(c)) for c in categories)

    # finding cards
    fcards = []
    for idx, f in enumerate(vulns):
        rid = "ev%d" % idx
        rem_lines = [re.sub(r"^\s*\d{1,2}[.)]\s+", "", l.strip())
                     for l in f.remediation.split("\n") if l.strip()]
        rem_html = "".join("<li>%s</li>" % esc(l) for l in rem_lines) or "<li>No action required.</li>"
        fcards.append(
            (
            '<div class="finding" style="border-left-color:{col}" data-sev="{sev}" '
            'data-cat="{cat}" data-text="{txt}">'
            '<div class="top"><span class="fid">{cid}</span><h3>{name}</h3>'
            '{hostchip}{vchip}{schip}</div>'
            '<div class="body">'
            '<div class="row"><div class="lab">Exact location'
            '<button class="copy" data-copy="loc{id}">Copy</button></div>'
            '<div class="loc" id="loc{id}">{loc}</div></div>'
            '<div class="row"><div class="lab">Evidence - what was found'
            '<button class="copy" data-copy="ev{id}">Copy</button></div>'
            '<pre id="ev{id}">{ev}</pre></div>'
            '<div class="row"><div class="lab">Why this matters</div>'
            '<div class="desc">{desc}</div></div>'
            '<div class="row"><div class="lab">Remediation'
            '<button class="copy" data-copy="rem{id}">Copy</button></div>'
            '<div class="remediation" id="rem{id}"><ol>{rem}</ol></div></div>'
            '</div></div>'
            ).format(col=SEV_COLORS.get(f.severity, "#64748b"), sev=esc(f.severity),
                 cat=esc(f.category), txt=esc(("%s %s %s %s" % (f.name, f.location,
                                                                f.evidence, f.description)).lower()),
                 cid=esc(f.check_id), name=esc(f.name),
                 hostchip=('<span class="hosttag">&#9642; %s</span>' % esc(f.host))
                          if getattr(f, "host", "local") not in ("local", None, "")
                          else "",
                 vchip='<span class="chip vuln">VULNERABLE</span>',
                 schip=_sev_chip(f.severity, f.score),
                 id=str(idx), loc=esc(f.location), ev=esc(f.evidence),
                 desc=esc(f.description), rem=rem_html))
    findings_html = "".join(fcards) or (
        '<div class="finding" style="border-left-color:var(--ok)">'
        '<h3>No vulnerable findings matched the current filters.</h3></div>')

    # test log
    trows = []
    for i, t in enumerate(tests, 1):
        trows.append(
            "<tr><td>%d</td><td class='mono'>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td><td class='mono'>%s</td><td>%d&nbsp;ms</td></tr>"
            % (i, esc(t["check_id"]), esc(t["name"]), esc(t["category"]),
               esc(t.get("host", "local")), _chip(t["status"]),
               esc(t["locations"]) or "&mdash;", t["duration_ms"]))
    tests_html = "".join(trows)

    doc = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{tool} Report - {host}</title>
<style>{css}</style></head>
<body>
<header><div class="wrap">
  <div class="brand">{shield}<div>
    <h1>{tool} {ver} - System Vulnerability Audit Report</h1>
    <div class="sub">{title} &middot; {host} &middot; {os_pretty} &middot; {date} &middot; {dur}s scan</div>
  </div></div>
  {banner}
</div></header>
<div class="wrap">
  <div class="meta">{meta}</div>
  <div class="cards">{cards}</div>
  <h2>Vulnerability details ({nvuln})</h2>
  <div class="toolbar">
    {btns}
    <select id="cat">{cat_opts}</select>
    <input id="q" type="search" placeholder="Search findings (name, path, evidence)...">
    <button class="sev-btn" id="toggleAll">Collapse all evidence</button>
  </div>
  <div id="findings">{findings}</div>
  <h2>Full test log - {ntests} tests conducted on this system</h2>
  <table><thead><tr><th>#</th><th>ID</th><th>Test name</th><th>Category</th>
  <th>Host</th><th>Result</th><th>Location(s)</th><th>Duration</th></tr></thead>
  <tbody>{tests}</tbody></table>
  <footer>
    <b>Scoring:</b> severity scores are Hooky internal estimates aligned to CVSS v3 bands ({bands}).
    CVE matches (PK-004) are OFFLINE version-signature results - distributions often backport fixes without a
    version bump, so always confirm against the vendor advisory before acting.
    <br><b>Scope:</b>{scope_extra} results cover the local filesystem, kernel, users, services and package database
    reachable by Hooky at scan time; network-reachable vulnerabilities on OTHER hosts are out of scope.
    Tests marked SKIPPED require root privileges or a missing subsystem - re-run as root for full coverage.
    <br>Only audit systems you own or are explicitly authorised to assess.
    <br>Generated by {tool} {ver} (Python {py}) on {date} in {dur}s &middot; reports: HTML / PDF / JSON / CSV.
  </footer>
</div>
<script>{js}</script>
</body></html>"""
    out = doc.format(css=_CSS, js=_JS, shield=_SHIELD, tool=TOOL_NAME, ver=TOOL_VERSION,
                     host=esc(host), title=esc(title), os_pretty=esc(md.get("os")),
                     date=esc(md.get("audit_time")), dur=summary["duration_seconds"],
                     banner=banner, meta=meta_html, cards=cards_html, btns=btn_html,
                     cat_opts=cat_opts, nvuln=len(vulns), findings=findings_html,
                     ntests=len(tests), tests=tests_html, py=esc(md.get("python")),
                     bands=SEV_SCORE_BANDS,
                     scope_extra=(" Windows target(s) were audited through the read-only "
                                  "Hooky agent, whose collectors snapshot the target "
                                  "configuration without changing it;" if targets
                                  else ""))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)
    return path
