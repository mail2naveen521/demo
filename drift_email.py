#!/usr/bin/env python3
"""
drift_email.py
WebSphere ND 8.5.5 — Configuration Drift Detection
Reads the JSON drift report and sends a polished HTML email.
"""

import argparse
import json
import os
import smtplib
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ---------------------------------------------------------------------------
# Optional: set if your SMTP relay requires authentication
# ---------------------------------------------------------------------------
SMTP_USER = os.environ.get("DRIFT_SMTP_USER", "")
SMTP_PASS = os.environ.get("DRIFT_SMTP_PASS", "")


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def severity_badge(label: str, color: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
        f'font-size:11px;font-weight:700;letter-spacing:.5px;'
        f'background:{color};color:#fff;">{label}</span>'
    )


def diff_to_html(diff_text: str) -> str:
    """Convert unified diff text to colour-coded HTML."""
    if not diff_text or diff_text.strip() in ("FILE_REMOVED", "FILE_ADDED"):
        return f'<em style="color:#888">{diff_text.strip()}</em>'

    lines_html = []
    for line in diff_text.splitlines():
        esc = (line
               .replace("&", "&amp;")
               .replace("<", "&lt;")
               .replace(">", "&gt;"))
        if line.startswith("+++") or line.startswith("---"):
            style = "color:#888;font-style:italic"
        elif line.startswith("+"):
            style = "background:#d4edda;color:#155724"
        elif line.startswith("-"):
            style = "background:#f8d7da;color:#721c24"
        elif line.startswith("@@"):
            style = "background:#cce5ff;color:#004085"
        else:
            style = "color:#333"
        lines_html.append(
            f'<div style="font-family:monospace;font-size:12px;'
            f'padding:1px 6px;white-space:pre;{style}">{esc}</div>'
        )
    return "\n".join(lines_html)


def file_category(path: str) -> str:
    """Return a human-readable category for a given config path."""
    p = path.lower()
    if "resources.xml" in p:
        return "resources.xml"
    if "server.xml" in p:
        return "server.xml"
    if "security.xml" in p or "security_config" in p:
        return "Security"
    if "jvm" in p or "javavirtu" in p:
        return "JVM"
    if "threadpool" in p:
        return "Thread Pool"
    if "datasource" in p:
        return "DataSource"
    if "jdbc" in p:
        return "JDBC"
    if "virtualhost" in p or "vhost" in p:
        return "Virtual Host"
    if "app_" in p or "applicationdeployment" in p:
        return "Application"
    if "cluster" in p:
        return "Cluster"
    if "variable" in p:
        return "WAS Variables"
    if "sharedlib" in p:
        return "Shared Library"
    if "txservice" in p or "transaction" in p:
        return "Transaction"
    return "Configuration"


CATEGORY_COLORS = {
    "resources.xml": "#c0392b",
    "server.xml":    "#8e44ad",
    "Security":      "#c0392b",
    "JVM":           "#2980b9",
    "Thread Pool":   "#16a085",
    "DataSource":    "#d35400",
    "JDBC":          "#d35400",
    "Virtual Host":  "#27ae60",
    "Application":   "#2c3e50",
    "Cluster":       "#8e44ad",
    "WAS Variables": "#7f8c8d",
    "Shared Library":"#7f8c8d",
    "Transaction":   "#16a085",
    "Configuration": "#555",
}


# ---------------------------------------------------------------------------
# Build the HTML body
# ---------------------------------------------------------------------------

def build_html(report: dict, resources_drift_file: str) -> str:
    ts = report.get("check_time_human", report.get("check_timestamp", "N/A"))
    try:
        dt = datetime.fromisoformat(ts)
        ts_human = dt.strftime("%A, %d %b %Y  %H:%M:%S")
    except Exception:
        ts_human = ts

    dmgr   = report.get("dmgr_host", "N/A")
    cell   = report.get("cell_name", "N/A")
    cluster = report.get("cluster_name", "N/A")
    wsadmin_ok = report.get("wsadmin_ok", True)

    summary = report.get("summary", {})
    changed  = summary.get("changed_files", [])
    added    = summary.get("added_files", [])
    removed  = summary.get("removed_files", [])
    res_count = summary.get("resources_xml_drifts", 0)
    diff_details = report.get("diff_details", [])

    total_changes = len(changed) + len(added) + len(removed)

    # ---- Header ----
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebSphere Config Drift Detected</title>
</head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:'Segoe UI',Arial,sans-serif">

<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:30px 0">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;
       overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.12)">

  <!-- TOP BANNER -->
  <tr>
    <td style="background:linear-gradient(135deg,#1a237e 0%,#283593 60%,#c62828 100%);
               padding:28px 36px;color:#fff">
      <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;
                  opacity:.75;margin-bottom:6px">WebSphere ND 8.5.5 · Drift Monitor</div>
      <div style="font-size:26px;font-weight:700;margin-bottom:4px">
        ⚠️&nbsp; Configuration Drift Detected
      </div>
      <div style="font-size:13px;opacity:.85">{ts_human}</div>
    </td>
  </tr>

  <!-- ENVIRONMENT STRIP -->
  <tr>
    <td style="background:#1a237e;padding:10px 36px">
      <table cellpadding="0" cellspacing="0">
        <tr>
          <td style="color:#90caf9;font-size:12px;padding-right:24px">
            <strong style="color:#fff">DMGR</strong>&nbsp;&nbsp;{dmgr}
          </td>
          <td style="color:#90caf9;font-size:12px;padding-right:24px">
            <strong style="color:#fff">Cell</strong>&nbsp;&nbsp;{cell}
          </td>
          <td style="color:#90caf9;font-size:12px">
            <strong style="color:#fff">Cluster</strong>&nbsp;&nbsp;{cluster}
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- SUMMARY CARDS -->
  <tr>
    <td style="padding:28px 36px 0">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
"""

    def stat_card(count, label, color, icon):
        return f"""
          <td width="23%" align="center" style="background:{color}12;border:1px solid {color}44;
              border-radius:8px;padding:16px 8px;margin:4px">
            <div style="font-size:32px;font-weight:800;color:{color}">{icon} {count}</div>
            <div style="font-size:11px;color:#555;text-transform:uppercase;
                        letter-spacing:.8px;margin-top:4px">{label}</div>
          </td>
          <td width="2%"></td>
"""

    html += stat_card(len(changed),  "Changed Files",      "#e65100", "✏️")
    html += stat_card(len(added),    "Added Files",        "#1b5e20", "➕")
    html += stat_card(len(removed),  "Removed Files",      "#b71c1c", "🗑️")
    html += stat_card(res_count,     "resources.xml Drifts","#4a148c","📄")

    html += """
        </tr>
      </table>
    </td>
  </tr>
"""

    if not wsadmin_ok:
        html += """
  <tr>
    <td style="padding:16px 36px 0">
      <div style="background:#fff3e0;border-left:4px solid #ff6f00;padding:10px 16px;
                  border-radius:4px;font-size:13px;color:#e65100">
        <strong>⚠ wsadmin live dump failed</strong> — comparison is based on
        DMGR config repository files only. Check the log for details.
      </div>
    </td>
  </tr>
"""

    # ---- resources.xml section ----
    resources_rows = []
    if os.path.isfile(resources_drift_file):
        with open(resources_drift_file) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("RESOURCES_DRIFT:::"):
                    parts = line.split(":::", 2)
                    if len(parts) == 3:
                        resources_rows.append((parts[1], parts[2]))

    if resources_rows:
        html += """
  <tr>
    <td style="padding:24px 36px 0">
      <div style="font-size:16px;font-weight:700;color:#c62828;border-bottom:2px solid #c62828;
                  padding-bottom:6px;margin-bottom:16px">
        📄 resources.xml Changes
      </div>
"""
        for rel_path, diff_text in resources_rows:
            status = "FILE_ADDED" if diff_text == "FILE_ADDED" else \
                     "FILE_REMOVED" if diff_text == "FILE_REMOVED" else "MODIFIED"
            badge_color = "#1b5e20" if status == "FILE_ADDED" else \
                          "#b71c1c" if status == "FILE_REMOVED" else "#e65100"
            html += f"""
      <div style="margin-bottom:16px;border:1px solid #eee;border-radius:6px;overflow:hidden">
        <div style="background:#fbe9e7;padding:8px 14px;display:flex;align-items:center;
                    justify-content:space-between">
          <span style="font-family:monospace;font-size:12px;color:#333;word-break:break-all">
            {rel_path}
          </span>
          {severity_badge(status, badge_color)}
        </div>
        <div style="padding:0;overflow-x:auto">
          {diff_to_html(diff_text)}
        </div>
      </div>
"""
        html += "    </td>\n  </tr>\n"

    # ---- Changed files detail ----
    if diff_details:
        html += """
  <tr>
    <td style="padding:24px 36px 0">
      <div style="font-size:16px;font-weight:700;color:#1a237e;border-bottom:2px solid #1a237e;
                  padding-bottom:6px;margin-bottom:16px">
        ✏️ Detailed File Diffs
      </div>
"""
        for entry in diff_details:
            fp = entry.get("file", "unknown")
            diff_text = entry.get("diff", "")
            cat = file_category(fp)
            cat_color = CATEGORY_COLORS.get(cat, "#555")
            html += f"""
      <div style="margin-bottom:16px;border:1px solid #e8eaf6;border-radius:6px;overflow:hidden">
        <div style="background:#e8eaf6;padding:8px 14px;display:flex;align-items:center;
                    gap:10px;flex-wrap:wrap">
          {severity_badge(cat, cat_color)}
          <span style="font-family:monospace;font-size:12px;color:#333;
                       flex:1;word-break:break-all">{fp}</span>
        </div>
        <div style="overflow-x:auto">
          {diff_to_html(diff_text)}
        </div>
      </div>
"""
        html += "    </td>\n  </tr>\n"

    # ---- Added files list ----
    truly_added = [f for f in added if f not in changed]
    if truly_added:
        html += """
  <tr>
    <td style="padding:24px 36px 0">
      <div style="font-size:16px;font-weight:700;color:#1b5e20;border-bottom:2px solid #1b5e20;
                  padding-bottom:6px;margin-bottom:12px">➕ Newly Added Files</div>
      <ul style="margin:0;padding-left:20px">
"""
        for f in truly_added:
            html += f'        <li style="font-family:monospace;font-size:12px;color:#333;margin:4px 0">{f}</li>\n'
        html += "      </ul>\n    </td>\n  </tr>\n"

    # ---- Removed files list ----
    truly_removed = [f for f in removed if f not in changed]
    if truly_removed:
        html += """
  <tr>
    <td style="padding:24px 36px 0">
      <div style="font-size:16px;font-weight:700;color:#b71c1c;border-bottom:2px solid #b71c1c;
                  padding-bottom:6px;margin-bottom:12px">🗑️ Removed Files</div>
      <ul style="margin:0;padding-left:20px">
"""
        for f in truly_removed:
            html += f'        <li style="font-family:monospace;font-size:12px;color:#333;margin:4px 0">{f}</li>\n'
        html += "      </ul>\n    </td>\n  </tr>\n"

    # ---- Footer ----
    html += f"""
  <!-- FOOTER -->
  <tr>
    <td style="padding:24px 36px;margin-top:24px;background:#f5f5f5;
               border-top:1px solid #e0e0e0;font-size:11px;color:#888;text-align:center">
      Generated by WebSphere ND 8.5.5 Drift Monitor &nbsp;·&nbsp;
      Host: {dmgr} &nbsp;·&nbsp; {ts_human}<br>
      <span style="color:#aaa">To reset the baseline, re-run extract_baseline.sh</span>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Plain-text fallback
# ---------------------------------------------------------------------------

def build_plaintext(report: dict, resources_drift_file: str) -> str:
    summary = report.get("summary", {})
    lines = [
        "=" * 70,
        "WebSphere ND 8.5.5 — CONFIGURATION DRIFT DETECTED",
        "=" * 70,
        f"Time     : {report.get('check_time_human', 'N/A')}",
        f"DMGR     : {report.get('dmgr_host', 'N/A')}",
        f"Cell     : {report.get('cell_name', 'N/A')}",
        f"Cluster  : {report.get('cluster_name', 'N/A')}",
        "",
        f"Changed files  : {len(summary.get('changed_files', []))}",
        f"Added files    : {len(summary.get('added_files', []))}",
        f"Removed files  : {len(summary.get('removed_files', []))}",
        f"resources.xml  : {summary.get('resources_xml_drifts', 0)} changes",
        "",
    ]

    if os.path.isfile(resources_drift_file):
        lines.append("--- resources.xml DRIFTS ---")
        with open(resources_drift_file) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("RESOURCES_DRIFT:::"):
                    parts = line.split(":::", 2)
                    if len(parts) == 3:
                        lines.append(f"  FILE : {parts[1]}")
                        if parts[2] in ("FILE_ADDED", "FILE_REMOVED"):
                            lines.append(f"  STATUS: {parts[2]}")
                        else:
                            lines.append("  (diff truncated in plain text — see HTML version)")
                        lines.append("")

    for entry in report.get("diff_details", []):
        lines.append(f"--- {entry.get('file', '?')} ---")
        lines.append(entry.get("diff", "")[:2000])   # cap for plain text
        lines.append("")

    lines.append("=" * 70)
    lines.append("To reset the baseline: re-run extract_baseline.sh")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Send WebSphere drift email")
    parser.add_argument("--report",    required=True,  help="Path to JSON drift report")
    parser.add_argument("--resources", required=True,  help="Path to resources drift txt")
    parser.add_argument("--to",        required=True,  help="Recipient(s), comma-separated")
    parser.add_argument("--from",      dest="frm",     default="was-drift@localhost")
    parser.add_argument("--smtp-host", default="localhost")
    parser.add_argument("--smtp-port", type=int, default=25)
    args = parser.parse_args()

    if not os.path.isfile(args.report):
        print(f"ERROR: Report file not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    with open(args.report) as fh:
        report = json.load(fh)

    if not report.get("drift_detected", False):
        print("No drift in report — not sending email.")
        sys.exit(0)

    html_body  = build_html(report, args.resources)
    text_body  = build_plaintext(report, args.resources)

    ts_label = report.get("check_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
    cell     = report.get("cell_name", "WebSphere")
    subject  = f"[DRIFT ALERT] WebSphere {cell} config changed — {ts_label}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = args.frm
    msg["To"]      = args.to

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    recipients = [r.strip() for r in args.to.split(",")]

    try:
        with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=30) as smtp:
            if SMTP_USER and SMTP_PASS:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(args.frm, recipients, msg.as_string())
        print(f"Email sent to: {args.to}")
    except Exception as exc:
        print(f"ERROR sending email: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
