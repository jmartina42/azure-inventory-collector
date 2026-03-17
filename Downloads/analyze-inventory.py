#!/usr/bin/env python3
"""
Azure Inventory AI Analyzer
Reads an azure-inventory-data-*.json file and uses Claude to produce
a security, cost, and operational findings report.

Usage:
    python analyze-inventory.py <inventory.json> [--output report.html]

Requirements:
    pip install anthropic
    Set ANTHROPIC_API_KEY environment variable.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    import anthropic
except ImportError:
    print("ERROR: anthropic package not found. Run: pip install anthropic")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# PRE-ANALYSIS HELPERS
# ─────────────────────────────────────────────────────────────

def summarize_inventory(inv: dict) -> dict:
    """Extract key counts and notable items to keep the prompt concise."""
    summary = {}

    # VMs
    vms = inv.get("VMs", [])
    summary["vms"] = {
        "total": len(vms),
        "deallocated": [v["Name"] for v in vms if "deallocated" in (v.get("PowerState") or "").lower()],
        "stopped": [v["Name"] for v in vms if "stopped" in (v.get("PowerState") or "").lower()],
        "untagged": [v["Name"] for v in vms if not v.get("Tags") or v.get("Tags") in ("{}", "null", None, "")],
        "sizes": list({v.get("Size") for v in vms if v.get("Size")}),
    }

    # Disks
    disks = inv.get("Disks", [])
    summary["disks"] = {
        "total": len(disks),
        "unattached": [
            {"name": d["Name"], "sizeGB": d.get("SizeGB"), "sku": d.get("SKU")}
            for d in disks if d.get("AttachedTo") == "Unattached"
        ],
        "unencrypted": [d["Name"] for d in disks if not d.get("Encryption")],
    }

    # Storage accounts
    storage = inv.get("StorageAccounts", [])
    summary["storage"] = {
        "total": len(storage),
        "https_not_enforced": [s["Name"] for s in storage if not s.get("HTTPSOnly")],
        "public_blob_access": [s["Name"] for s in storage if s.get("AllowBlobPublic")],
        "old_tls": [
            {"name": s["Name"], "tls": s.get("TLSVersion")}
            for s in storage
            if s.get("TLSVersion") and s.get("TLSVersion") != "TLS1_2"
        ],
    }

    # Public IPs
    pips = inv.get("PublicIPs", [])
    summary["public_ips"] = {
        "total": len(pips),
        "unassociated": [
            {"name": p["Name"], "ip": p.get("IPAddress")}
            for p in pips if p.get("AssociatedTo") == "Unassociated"
        ],
        "dynamic": [p["Name"] for p in pips if p.get("AllocationMethod") == "Dynamic"],
    }

    # NSGs
    nsgs = inv.get("NSGs", [])
    summary["nsgs"] = {
        "total": len(nsgs),
        "unassociated": [n["Name"] for n in nsgs if not n.get("AssociatedTo")],
        "no_custom_rules": [
            n["Name"] for n in nsgs
            if (n.get("InboundRules", 0) + n.get("OutboundRules", 0)) == 0
        ],
    }

    # App Services / Functions
    apps = inv.get("AppServices", [])
    funcs = inv.get("Functions", [])
    summary["app_services"] = {
        "total": len(apps),
        "https_not_enforced": [a["Name"] for a in apps if not a.get("HTTPSOnly")],
        "stopped": [a["Name"] for a in apps if a.get("State") != "Running"],
    }
    summary["functions"] = {
        "total": len(funcs),
        "https_not_enforced": [f["Name"] for f in funcs if not f.get("HTTPSOnly")],
    }

    # VNets
    vnets = inv.get("VNets", [])
    summary["vnets"] = {
        "total": len(vnets),
        "no_dns_override": [v["Name"] for v in vnets if not v.get("DNSServers")],
        "no_peering": [v["Name"] for v in vnets if v.get("PeeringCount", 0) == 0],
    }

    # AVD
    summary["avd"] = {
        "host_pools": len(inv.get("AVDHostPools", [])),
        "session_hosts": len(inv.get("AVDSessionHosts", [])),
        "app_groups": len(inv.get("AVDAppGroups", [])),
        "unavailable_hosts": [
            h["Name"] for h in inv.get("AVDSessionHosts", [])
            if h.get("Status") not in ("Available", "NeedsAssistance")
            and h.get("Status")
        ],
    }

    # Subscriptions in scope
    all_items = vms + disks + storage + pips + nsgs + apps + funcs + vnets
    summary["subscriptions"] = list({i.get("Subscription") for i in all_items if i.get("Subscription")})

    return summary


def build_prompt(summary: dict, scan_time: str) -> str:
    s = json.dumps(summary, indent=2, default=str)
    return f"""You are an expert Azure cloud architect and security engineer.
Below is a pre-analyzed summary of an Azure inventory collected on {scan_time}.
Produce a concise but thorough findings report with three sections:

## 1. Security Findings
Identify risks such as unencrypted disks, storage accounts with public blob access or HTTP,
old TLS versions, unassociated public IPs (potential dangling DNS), apps without HTTPS enforcement,
and any other security concerns visible in the data.

## 2. Cost Optimization
Identify waste such as unattached (orphaned) disks, deallocated/stopped VMs still incurring
storage costs, unassociated public IPs (charged even when idle), stopped App Services still
on paid plans, and any oversized or redundant resources.

## 3. Operational Recommendations
Comment on AVD session host health, missing tags (cost-allocation/governance gap), NSGs with
no custom rules, VNets with no DNS override, and anything else worth noting for day-to-day operations.

For each finding include:
- **Severity**: Critical / High / Medium / Low
- **Affected resources**: list names
- **Recommendation**: specific action to take

End with a brief **Executive Summary** (3-5 bullets) of the most important actions.

---
INVENTORY SUMMARY:
{s}
"""


# ─────────────────────────────────────────────────────────────
# HTML REPORT TEMPLATE
# ─────────────────────────────────────────────────────────────

def render_html(analysis_md: str, scan_time: str, summary: dict) -> str:
    stats = [
        ("VMs", summary["vms"]["total"]),
        ("Disks", summary["disks"]["total"]),
        ("Storage Accounts", summary["storage"]["total"]),
        ("Public IPs", summary["public_ips"]["total"]),
        ("NSGs", summary["nsgs"]["total"]),
        ("App Services", summary["app_services"]["total"]),
        ("Functions", summary["functions"]["total"]),
        ("AVD Host Pools", summary["avd"]["host_pools"]),
    ]
    stat_html = "".join(
        f'<div class="stat"><span class="stat-num">{v}</span><span class="stat-label">{k}</span></div>'
        for k, v in stats
    )

    # Convert basic Markdown to HTML (headings, bold, lists)
    lines = []
    for line in analysis_md.splitlines():
        if line.startswith("## "):
            lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("- "):
            lines.append(f"<li>{_md_inline(line[2:])}</li>")
        elif line.startswith("---"):
            lines.append("<hr>")
        elif line.strip() == "":
            lines.append("<br>")
        else:
            lines.append(f"<p>{_md_inline(line)}</p>")
    body = "\n".join(lines)

    subs = ", ".join(summary.get("subscriptions", [])) or "N/A"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure Inventory AI Analysis — {scan_time}</title>
<style>
  :root {{
    --bg: #0f1117; --panel: #1a1d27; --accent: #0078d4;
    --text: #e0e0e0; --muted: #888; --border: #2e3245;
    --green: #3dba6e; --yellow: #f0c040; --red: #e05252;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
         font-size: 15px; line-height: 1.65; padding: 2rem; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.2rem; margin-bottom: 1.5rem; }}
  header h1 {{ font-size: 1.6rem; color: var(--accent); }}
  header .meta {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }}
  .stats {{ display: flex; flex-wrap: wrap; gap: 0.8rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
           padding: 0.8rem 1.2rem; min-width: 120px; text-align: center; }}
  .stat-num {{ display: block; font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
  .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
  .analysis {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
               padding: 2rem; max-width: 960px; }}
  h2 {{ color: var(--accent); font-size: 1.2rem; margin: 1.5rem 0 0.7rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }}
  h3 {{ color: #aac4e0; font-size: 1rem; margin: 1rem 0 0.4rem; }}
  p {{ margin: 0.4rem 0; }}
  li {{ margin: 0.25rem 0 0.25rem 1.5rem; }}
  strong {{ color: #fff; }}
  hr {{ border: none; border-top: 1px solid var(--border); margin: 1.2rem 0; }}
  br {{ display: block; margin: 0.3rem 0; content: ""; }}
  .badge-critical {{ color: var(--red); font-weight: 700; }}
  .badge-high {{ color: #e07832; font-weight: 700; }}
  .badge-medium {{ color: var(--yellow); font-weight: 700; }}
  .badge-low {{ color: var(--green); font-weight: 700; }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: 0.8rem; }}
</style>
</head>
<body>
<header>
  <h1>Azure Inventory — AI Analysis Report</h1>
  <div class="meta">Scan time: {scan_time} &nbsp;|&nbsp; Subscriptions: {subs}</div>
</header>
<div class="stats">{stat_html}</div>
<div class="analysis">{body}</div>
<footer>Generated by analyze-inventory.py using Claude Opus 4.6 &nbsp;|&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M")}</footer>
</body>
</html>"""


def _md_inline(text: str) -> str:
    """Convert **bold** and severity badges in inline text."""
    import re
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    for sev in ("Critical", "High", "Medium", "Low"):
        text = text.replace(f"**{sev}**", f'<span class="badge-{sev.lower()}">{sev}</span>')
        text = text.replace(sev, f'<span class="badge-{sev.lower()}">{sev}</span>', 1)
    return text


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyze Azure inventory with Claude AI")
    parser.add_argument("inventory", help="Path to azure-inventory-data-*.json")
    parser.add_argument("--output", "-o", help="Output HTML report path (default: <inventory>.analysis.html)")
    args = parser.parse_args()

    json_path = Path(args.inventory)
    if not json_path.exists():
        print(f"ERROR: File not found: {json_path}")
        sys.exit(1)

    output_path = Path(args.output) if args.output else json_path.with_suffix(".analysis.html")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set.")
        sys.exit(1)

    print(f"[*] Loading inventory: {json_path}")
    with open(json_path, encoding="utf-8") as f:
        inv = json.load(f)

    scan_time = inv.get("ScanTime") or inv.get("scanTime") or "unknown"
    print(f"[*] Scan time: {scan_time}")

    summary = summarize_inventory(inv)
    prompt = build_prompt(summary, scan_time)

    print("[*] Sending to Claude Opus 4.6 for analysis...\n")
    print("─" * 70)

    client = anthropic.Anthropic(api_key=api_key)
    analysis_text = ""

    with client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        for event in stream:
            if event.type == "content_block_delta":
                if hasattr(event.delta, "text"):
                    chunk = event.delta.text
                    print(chunk, end="", flush=True)
                    analysis_text += chunk

        final = stream.get_final_message()

    print("\n" + "─" * 70)
    print(f"\n[*] Analysis complete. Input tokens: {final.usage.input_tokens}, "
          f"Output tokens: {final.usage.output_tokens}")

    html = render_html(analysis_text, str(scan_time), summary)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[*] HTML report saved: {output_path}")


if __name__ == "__main__":
    main()
