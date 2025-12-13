# utils.py
"""
Utility helpers: JSON loading, report generation, and console output.

- Uses Rich for colorful, wrapped tables in the terminal; falls back to ASCII if Rich is not installed.
- Saves JSON, CSV, and HTML reports.
"""

from dataclasses import asdict
from datetime import datetime
from typing import List, Dict
import json
import csv
import os
from json import JSONDecodeError

# Prefer Rich for colorful, wrapped tables. If not available, fall back to a simple ASCII table.
try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    _HAS_RICH = True
    _console = Console()
except Exception:
    _HAS_RICH = False
    _console = None  # type: ignore

from models import Finding

def load_json_file(path: str) -> dict:
    """
    Load JSON from a file and return a Python dict.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Input JSON file not found: {path}.")
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e.msg} (line {e.lineno} column {e.colno})") from e

def ensure_reports_dir(path: str = "reports") -> str:
    os.makedirs(path, exist_ok=True)
    return path

def findings_to_json(findings: List[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)

def findings_to_table_rows(findings: List[Finding]) -> List[List[str]]:
    rows: List[List[str]] = []
    for f in findings:
        rows.append([str(f.resource), str(f.issue), str(f.severity), str(f.details or "")])
    return rows

def simple_ascii_table(headers: List[str], rows: List[List[str]]) -> str:
    """
    Minimal ASCII table generator used when Rich is not available.
    """
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            if i >= len(widths):
                widths.append(len(cell))
            else:
                widths[i] = max(widths[i], len(cell))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    def fmt_row(r: List[str]) -> str:
        cells = []
        for i, cell in enumerate(r):
            cells.append(" " + cell.ljust(widths[i]) + " ")
        return "|" + "|".join(cells) + "|"
    lines = [sep, fmt_row(headers), sep]
    for r in rows:
        lines.append(fmt_row(r))
    lines.append(sep)
    return "\n".join(lines)

def save_report(findings: List[Finding], mode: str, extra: dict = None, out_dir: str = "reports") -> Dict[str, str]:
    """
    Save JSON, CSV, and HTML reports and return their paths.
    """
    out_dir = ensure_reports_dir(out_dir)
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    report = {"scan_time": now, "mode": mode, "findings": [asdict(f) for f in findings]}
    if extra:
        report["extra"] = extra

    base_ts = now.replace(":", "-")
    json_path = os.path.join(out_dir, f"scan-{base_ts}-{mode}.json")
    csv_path = os.path.join(out_dir, f"scan-{base_ts}-{mode}.csv")
    html_path = os.path.join(out_dir, f"scan-{base_ts}-{mode}.html")

    # JSON
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # CSV
    fieldnames = ["resource", "issue", "severity", "details"]
    with open(csv_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in report["findings"]:
            row = {k: f.get(k, "") for k in fieldnames}
            writer.writerow(row)

    # HTML
    html_rows: List[str] = []
    html_rows.append("<!doctype html>")
    html_rows.append("<html><head><meta charset='utf-8'><title>Scan Report</title>")
    html_rows.append("<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f2f2f2;text-align:left}tr:nth-child(even){background:#fafafa}pre{white-space:pre-wrap;word-wrap:break-word}</style>")
    html_rows.append("</head><body>")
    html_rows.append(f"<h2>Scan Report - {now} - mode: {mode}</h2>")
    html_rows.append(f"<p>Total findings: {len(report['findings'])}</p>")
    if extra:
        html_rows.append("<div><strong>Metadata:</strong><ul>")
        for k, v in extra.items():
            html_rows.append(f"<li>{k}: {v}</li>")
        html_rows.append("</ul></div>")
    html_rows.append("<table><thead><tr><th>Resource</th><th>Issue</th><th>Severity</th><th>Details</th></tr></thead><tbody>")
    for f in report["findings"]:
        resource = str(f.get("resource", ""))
        issue = str(f.get("issue", ""))
        severity = str(f.get("severity", ""))
        details = str(f.get("details", ""))
        html_rows.append(f"<tr><td>{resource}</td><td>{issue}</td><td>{severity}</td><td><pre>{details}</pre></td></tr>")
    html_rows.append("</tbody></table></body></html>")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(html_rows))

    return {"json": json_path, "csv": csv_path, "html": html_path}

# --- Console printing with color/wrapping (Rich preferred) ---

def _rich_severity_text(sev: int):
    """
    Return a Rich Text object styled by severity.
    """
    if sev >= 8:
        return Text(str(sev), style="bold red")
    if sev >= 5:
        return Text(str(sev), style="bold yellow")
    return Text(str(sev), style="green")

def print_summary_and_report_path(findings: List[Finding], report_paths: Dict[str, str], show_top: int = 5, print_full_table: bool = False):
    """
    Print a compact summary and a colorful table of findings.

    - Uses Rich if available for colored, wrapped tables.
    - Falls back to ASCII table when Rich is not installed.
    """
    total = len(findings)
    print("\nScan summary:")
    print(f"- Total findings: {total}")
    if total:
        rows = findings_to_table_rows(findings)
        if _HAS_RICH and _console:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Resource", style="cyan", overflow="fold")
            table.add_column("Issue", style="magenta")
            table.add_column("Severity", justify="right")
            table.add_column("Details", overflow="fold")
            for r in (rows if print_full_table else rows[:show_top]):
                try:
                    sev = int(r[2])
                except Exception:
                    sev = 0
                table.add_row(r[0], r[1], _rich_severity_text(sev), r[3])
            _console.print(table)
        else:
            headers = ["Resource", "Issue", "Severity", "Details"]
            if print_full_table:
                print("\n" + simple_ascii_table(headers, rows))
            else:
                print("\n" + simple_ascii_table(headers, rows[:show_top]))
    print("\nSaved reports:")
    print(f"- JSON: {report_paths.get('json')}")
    print(f"- CSV:  {report_paths.get('csv')}")
    print(f"- HTML: {report_paths.get('html')}\n")
