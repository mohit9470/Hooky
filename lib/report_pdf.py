#!/usr/bin/env python3
"""Hooky - formal PDF report generator (ReportLab platypus)."""

import re

from xml.sax.saxutils import escape as xesc
from .core import SEVERITY_ORDER, TOOL_NAME, TOOL_VERSION, SEV_SCORE_BANDS, CVE_DB_DATE

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, PageBreak, KeepTogether)
    HAVE_REPORTLAB = True
except ImportError:  # pragma: no cover
    HAVE_REPORTLAB = False

SEV_HEX = {
    "CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#b45309",
    "LOW": "#1d4ed8", "INFO": "#475569", "SECURE": "#15803d", "SKIPPED": "#64748b",
}
NAVY = colors.HexColor("#0f172a")
ACCENT = colors.HexColor("#0e7490")
GREY = colors.HexColor("#64748b")
LINE = colors.HexColor("#cbd5e1")
SEVBG = {
    "CRITICAL": colors.HexColor("#fee2e2"), "HIGH": colors.HexColor("#ffedd5"),
    "MEDIUM": colors.HexColor("#fef3c7"), "LOW": colors.HexColor("#dbeafe"),
    "INFO": colors.HexColor("#f1f5f9"), "SECURE": colors.HexColor("#dcfce7"),
    "SKIPPED": colors.HexColor("#f1f5f9"),
}


def _br(text, max_chars=800):
    """Escape + convert newlines for Paragraph, truncate very long evidence."""
    t = str(text or "")
    if len(t) > max_chars:
        t = t[:max_chars] + "\n... (truncated)"
    return xesc(t).replace("\n", "<br/>")


def _styles():
    s = {}
    s["title"] = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20,
                                leading=24, textColor=NAVY, spaceAfter=2)
    s["subtitle"] = ParagraphStyle("subtitle", fontName="Helvetica", fontSize=10.5,
                                   leading=14, textColor=GREY, spaceAfter=10)
    s["h2"] = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13.5,
                             leading=17, textColor=ACCENT, spaceBefore=14,
                             spaceAfter=6)
    s["fh"] = ParagraphStyle("fh", fontName="Helvetica-Bold", fontSize=11.5,
                             leading=15, textColor=NAVY, spaceBefore=10,
                             spaceAfter=2)
    s["body"] = ParagraphStyle("body", fontName="Helvetica", fontSize=9.5,
                               leading=13.5, alignment=TA_LEFT, spaceAfter=4)
    s["label"] = ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8,
                                leading=11, textColor=GREY, spaceBefore=6)
    s["mono"] = ParagraphStyle("mono", fontName="Courier", fontSize=7.8,
                               leading=10.5, textColor=colors.HexColor("#1e293b"),
                               backColor=colors.HexColor("#f1f5f9"), borderPadding=4,
                               spaceAfter=4)
    s["small"] = ParagraphStyle("small", fontName="Helvetica", fontSize=8,
                                leading=11, textColor=GREY)
    s["tcell"] = ParagraphStyle("tcell", fontName="Helvetica", fontSize=8,
                                leading=10.5, textColor=colors.HexColor("#0f172a"))
    return s


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(15 * mm, 10 * mm,
                      "%s %s  -  system vulnerability audit  -  authorised use only"
                      % (TOOL_NAME, TOOL_VERSION))
    canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def generate_pdf(md, summary, findings, tests, path, title):
    if not HAVE_REPORTLAB:
        raise ImportError("reportlab is not installed - PDF skipped "
                          "(pip install reportlab)")
    st = _styles()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=15 * mm,
                            rightMargin=15 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm,
                            title="Hooky Vulnerability Audit Report - %s"
                                  % md.get("hostname", ""))
    story = []

    # ---------------- header ----------------
    story.append(Paragraph("%s %s" % (TOOL_NAME, TOOL_VERSION), st["subtitle"]))
    story.append(Paragraph("System Vulnerability Audit Report", st["title"]))
    story.append(Paragraph(escape_sub("%s | target: %s (%s) | %s"
                                      % (title, md.get("fqdn") or md.get("hostname"),
                                         md.get("os"), md.get("audit_time"))), st["subtitle"]))
    story.append(Spacer(1, 4))

    # ---------------- system information ----------------
    story.append(Paragraph("1. Audited System", st["h2"]))
    info_rows = [
        ["System name (FQDN)", md.get("fqdn") or md.get("hostname")],
        ["Hostname", md.get("hostname")],
        ["Hardware / platform model", md.get("hardware_model")],
        ["Virtualisation", md.get("virtualization")],
        ["Machine ID", md.get("machine_id")],
        ["Operating system", md.get("os")],
        ["Kernel / architecture", "%s / %s" % (md.get("kernel"), md.get("arch"))],
        ["Primary IP address", md.get("ip")],
        ["CPU", "%s (x%d cores)" % (md.get("cpu"), md.get("cpu_count") or 1)],
        ["Memory", md.get("memory")],
        ["Uptime at audit", md.get("uptime")],
        ["Audit date", md.get("audit_time")],
        ["Executed by", "%s (%s)" % (md.get("user"),
                                     "root" if md.get("privileged")
                                     else "unprivileged user - reduced coverage")],
        ["Scanned by", md.get("tool") + " (Python " + md.get("python", "") + ")"],
        ["Audited Windows targets" if md.get("remote_targets") else "Audit scope",
         " | ".join("%s (%s): %d finding(s)"
                    % (t.get("computer"), t.get("os"), t.get("findings", 0))
                    for t in (md.get("remote_targets") or []))
         or "local Linux host"],
        ["Audit title", title],
    ]
    t = Table([[Paragraph("<b>%s</b>" % xesc(k), st["tcell"]),
                Paragraph(xesc(str(v)), st["tcell"])] for k, v in info_rows],
              colWidths=[52 * mm, 128 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(t)

    # ---------------- executive summary ----------------
    story.append(Paragraph("2. Executive Summary", st["h2"]))
    sev = summary["by_severity"]
    if summary["tests_vulnerable"]:
        verdict = ("The audit identified %d vulnerable test result(s): %d Critical, "
                   "%d High, %d Medium and %d Low. The overall risk rating of this "
                   "system is %s based on the highest-severity confirmed finding. "
                   "Critical and High findings should be remediated first - each "
                   "one is a concrete, known path to system compromise."
                   % (summary["tests_vulnerable"], sev["CRITICAL"], sev["HIGH"],
                      sev["MEDIUM"], sev["LOW"], summary["risk_rating"]))
    else:
        verdict = ("None of the executed tests produced a vulnerable result. "
                   "%d test(s) could not be executed in this environment (see the "
                   "test log); re-run the audit with elevated privileges for full "
                   "coverage." % summary["tests_skipped"])
    story.append(Paragraph(
        "%d automated security tests were conducted on %s (%s) on %s by %s %s. "
        "Of these, %d returned VULNERABLE results, %d passed and %d were skipped "
        "(environment did not permit execution). %s"
        % (summary["total_tests"], xesc(md.get("fqdn") or md.get("hostname")),
           xesc(md.get("os")), xesc(md.get("audit_time")), TOOL_NAME, TOOL_VERSION,
           summary["tests_vulnerable"], summary["tests_secure"],
           summary["tests_skipped"], verdict), st["body"]))
    if md.get("remote_targets"):
        story.append(Paragraph(
            "Windows coverage: %d remote Windows target(s) were audited through "
            "the read-only Hooky agent: %s. Their findings carry the host "
            "name and WIN-xxx test IDs below and in the full test log."
            % (len(md["remote_targets"]),
               "; ".join(str(t.get("computer")) for t in md["remote_targets"])),
            st["body"]))

    sum_rows = [["Total tests conducted", str(summary["total_tests"])],
                ["Tests passed (SECURE)", str(summary["tests_secure"])],
                ["Tests with findings (VULNERABLE)", str(summary["tests_vulnerable"])],
                ["Informational results", str(summary["tests_informational"])],
                ["Tests skipped", str(summary["tests_skipped"])],
                ["Critical findings", str(sev["CRITICAL"])],
                ["High findings", str(sev["HIGH"])],
                ["Medium findings", str(sev["MEDIUM"])],
                ["Low findings", str(sev["LOW"])],
                ["Overall risk rating", summary["risk_rating"]]]
    t2 = Table([[Paragraph("<b>%s</b>" % xesc(a), st["tcell"]),
                 Paragraph(xesc(b), st["tcell"])] for a, b in sum_rows],
               colWidths=[110 * mm, 70 * mm])
    t2.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (0, 9), (-1, 9), SEVBG.get(summary["risk_rating"], colors.white)),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(t2)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Scoring:</b> severity scores are internal estimates aligned to CVSS v3 "
        "bands (%s). " % SEV_SCORE_BANDS +
        "<b>CVE matches (PK-004)</b> are offline version-signature results against "
        "Hooky's built-in database (snapshot %s); distributions frequently "
        "backport fixes without a version bump - confirm with the vendor advisory "
        "before remediation decisions." % CVE_DB_DATE, st["small"]))
    story.append(PageBreak())

    # ---------------- vulnerability details ----------------
    vulns = [f for f in findings if f.status == "VULNERABLE"]
    vulns.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.score))
    story.append(Paragraph("3. Vulnerability Details (VULNERABLE findings)", st["h2"]))
    if not vulns:
        story.append(Paragraph("No vulnerable findings. All executed tests passed.",
                               st["body"]))
    for n, f in enumerate(vulns, 1):
        sevcol = SEV_HEX.get(f.severity, "#475569")
        block = []
        block.append(Paragraph(
            '<font color="%s">[%s]</font> &nbsp;%d. %s'
            % (sevcol, xesc(f.severity), n, xesc(f.name)), st["fh"]))
        host_note = (" | Host: <b>%s</b>" % xesc(f.host)
                     if getattr(f, "host", "local") not in ("local", None, "")
                     else "")
        block.append(Paragraph(
            "Status: <b>VULNERABLE</b> | Severity: <b><font color='%s'>%s</font>"
            "</b> | Score: <b>%.1f/10</b> | Test ID: %s | Category: %s%s"
            % (sevcol, xesc(f.severity), f.score, xesc(f.check_id),
               xesc(f.category), host_note), st["small"]))
        block.append(Paragraph("Exact location", st["label"]))
        block.append(Paragraph(_br(f.location, 300), st["mono"]))
        if f.evidence:
            block.append(Paragraph("What was found (evidence)", st["label"]))
            block.append(Paragraph(_br(f.evidence, 700), st["mono"]))
        block.append(Paragraph("Why this matters", st["label"]))
        block.append(Paragraph(_br(f.description, 900), st["body"]))
        block.append(Paragraph("Remediation", st["label"]))
        rem_lines = [re.sub(r"^\s*\d{1,2}[.)]\s+", "", l.strip())
                     for l in f.remediation.split("\n") if l.strip()] \
            or ["No action required."]
        rem_html = "<br/>".join("<b>%d.</b> %s" % (i, _br(l, 500))
                                for i, l in enumerate(rem_lines, 1))
        block.append(Paragraph(rem_html,
                               ParagraphStyle("rem", parent=st["body"], leftIndent=12)))
        if n < len(vulns):
            block.append(Spacer(1, 8))
        if len(block) <= 8:
            story.append(KeepTogether(block))
        else:
            story.extend(block)

    # ---------------- test log ----------------
    story.append(Paragraph("4. Full Test Log - every test conducted on this system",
                           st["h2"]))
    story.append(Paragraph(
        "The table lists every audit test with its exact result. "
        "VULNERABLE = one or more vulnerable findings (details in section 3); "
        "SECURE = control verified in hardened state; INFO = informational "
        "inventory; SKIPPED = requires root privileges or a subsystem not present.",
        st["small"]))
    header = ["#", "ID", "Test name", "Category", "Host", "Result",
              "Location(s)", "ms"]
    widths = [8 * mm, 14 * mm, 40 * mm, 24 * mm, 20 * mm, 22 * mm, 42 * mm,
              10 * mm]
    rows = [[Paragraph("<b>%s</b>" % xesc(h),
                       ParagraphStyle("th", parent=st["tcell"], fontSize=7.5,
                                      textColor=colors.white)) for h in header]]
    for i, trow in enumerate(tests, 1):
        rows.append([
            Paragraph(str(i), st["tcell"]),
            Paragraph(xesc(trow["check_id"]), st["tcell"]),
            Paragraph(xesc(trow["name"]), st["tcell"]),
            Paragraph(xesc(trow["category"]), st["tcell"]),
            Paragraph(xesc(trow.get("host", "local")), st["tcell"]),
            Paragraph("<b>%s</b>" % xesc(trow["status"]), st["tcell"]),
            Paragraph(xesc(trow["locations"][:160]) or "-", st["tcell"]),
            Paragraph(str(trow["duration_ms"]), st["tcell"]),
        ])
    tl = Table(rows, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    for i, trow in enumerate(tests, 1):
        style.append(("BACKGROUND", (5, i), (5, i),
                      SEVBG.get(trow["status"], colors.white)))
    tl.setStyle(TableStyle(style))
    story.append(tl)

    # ---------------- methodology & limits ----------------
    story.append(Paragraph("5. Method, Scope & Limitations", st["h2"]))
    win_method = ""
    if md.get("remote_targets"):
        win_method = (" Windows hosts were audited through the bundled Hooky "
                      "PowerShell agent, whose read-only collectors snapshot "
                      "accounts, policy, services and network state without "
                      "changing the target.")
    story.append(Paragraph(
        "Hooky audited the local Linux host: filesystem permissions, account "
        "and privilege configuration, kernel network settings, listening services, "
        "the installed package set, and credential/material exposure.%s It performs "
        "no intrusive network exploitation and changes no system state (read-only "
        "audit). Offline CVE signatures date from %s; zero-day and runtime "
        "vulnerabilities are out of scope. Tests marked SKIPPED were not executed "
        "- typically because they require root privileges, so an unprivileged run "
        "covers a subset of the catalogue. This report is a point-in-time snapshot "
        "and complements, but does not replace, continuous vulnerability "
        "management, log monitoring and vendor advisories. Only audit systems you "
        "own or are explicitly authorised to assess." % (win_method, CVE_DB_DATE),
        st["body"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return path


def escape_sub(text):
    return xesc(text)
