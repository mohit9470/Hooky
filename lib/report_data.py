#!/usr/bin/env python3
"""Hooky - JSON and CSV report writers."""

import csv
import json
from .core import SEVERITY_ORDER


def build_summary(findings, tests, duration_s):
    vuln_findings = [f for f in findings if f.status == "VULNERABLE"]
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in vuln_findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1
    test_status = {"VULNERABLE": 0, "SECURE": 0, "INFO": 0, "SKIPPED": 0}
    for t in tests:
        test_status[t["status"]] = test_status.get(t["status"], 0) + 1
    return {
        "total_tests": len(tests),
        "tests_vulnerable": test_status["VULNERABLE"],
        "tests_secure": test_status["SECURE"],
        "tests_informational": test_status["INFO"],
        "tests_skipped": test_status["SKIPPED"],
        "findings_total": len(findings),
        "findings_vulnerable": len(vuln_findings),
        "by_severity": sev_counts,
        "duration_seconds": round(duration_s, 1),
        "risk_rating": ("CRITICAL" if sev_counts["CRITICAL"] else
                        "HIGH" if sev_counts["HIGH"] else
                        "MEDIUM" if sev_counts["MEDIUM"] else
                        "LOW" if sev_counts["LOW"] else "CLEAN"),
    }


def write_json(md, summary, findings, tests, path, title):
    payload = {
        "tool": md.get("tool", "Hooky"),
        "schema_version": "1.0",
        "title": title,
        "system": md,
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
        "tests": tests,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    return path


CSV_COLUMNS = ["host", "check_id", "test_name", "category", "status",
               "severity", "severity_score", "location", "evidence",
               "description", "remediation"]


def write_csv(findings, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        w.writerow(CSV_COLUMNS)
        for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9),
                                                 -x.score)):
            w.writerow([getattr(f, "host", "local"),
                        f.check_id, f.name, f.category, f.status, f.severity,
                        f.score,
                        f.location.replace("\n", " | "),
                        f.evidence.replace("\n", " | "),
                        f.description.replace("\n", " "),
                        f.remediation.replace("\n", " ")])
    return path
