# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Azure Inventory Collector — a dual-platform tool (Bash + PowerShell) that collects Azure resource inventory and produces interactive HTML reports. No build system or package manager is involved; this is pure scripting.

## Running the Scripts

**Bash (Linux/macOS):**
```bash
./azure-inventory.sh
./azure-inventory.sh --subscriptions "sub-id-1 sub-id-2" --output /tmp/reports
```

**PowerShell (Windows):**
```powershell
.\Azure-Inventory.ps1
.\Azure-Inventory.ps1 -SubscriptionIds "sub-id-1","sub-id-2" -OutputPath "C:\Reports"
```

**Prerequisites:**
- Bash: `azure-cli` and `jq`
- PowerShell: Az modules (`Az.Accounts`, `Az.Compute`, `Az.Network`, `Az.Storage`, `Az.Websites`, `Az.DesktopVirtualization`)

## Architecture

The project has a strict separation between data collection and presentation:

1. **Collection scripts** (`azure-inventory.sh` / `Azure-Inventory.ps1`) — authenticate to Azure, loop over subscriptions, and query 11 resource types (VMs, Disks, VNets, NSGs, Public IPs, Storage Accounts, App Services, Function Apps, AVD Host Pools, Session Hosts, App Groups). Both scripts produce an identical JSON schema.

2. **Output** — a timestamped JSON file (`azure-inventory-data-YYYYMMDD-HHMM.json`).

3. **Viewer** (`report-template.html`) — a standalone browser app. The user uploads the JSON file; it renders sortable/filterable tables with CSV export, dark theme UI, and color-coded status indicators. No backend or server is needed.

## Key Implementation Notes

- **Bash** uses `set -euo pipefail` strict mode; failed Azure queries fall back to `|| echo "[]"`.
- **PowerShell** uses `$ErrorActionPreference = "Continue"`; AVD operations are wrapped in try-catch with 20–30 s timeouts to prevent hangs.
- Both scripts must remain schema-compatible — changes to JSON field names affect the HTML viewer.
- The HTML report is entirely client-side (Vanilla JS); no frameworks or CDN dependencies.
