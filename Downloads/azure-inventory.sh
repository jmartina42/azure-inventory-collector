#!/usr/bin/env bash
# ============================================================
#  Azure Full Inventory Collector — Azure CLI Version
#  Generates a self-contained HTML report
# ============================================================
# REQUIREMENTS: azure-cli, jq
# USAGE:
#   chmod +x azure-inventory.sh
#   ./azure-inventory.sh
#   ./azure-inventory.sh --subscriptions "sub-id-1 sub-id-2" --output /tmp/reports
# ============================================================

set -euo pipefail

SUBSCRIPTIONS=""
OUTPUT_DIR="$(pwd)"
REPORT_FILE=""
SCAN_TIME=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# ── Parse args ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --subscriptions|-s) SUBSCRIPTIONS="$2"; shift 2 ;;
        --output|-o)        OUTPUT_DIR="$2";    shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Ensure output directory exists ──────────────────────────
mkdir -p "$OUTPUT_DIR" || { echo "[ERROR] Cannot create output dir: $OUTPUT_DIR"; exit 1; }

# ── Prereq checks ───────────────────────────────────────────
for cmd in az jq; do
    if ! command -v $cmd &>/dev/null; then
        echo "[ERROR] '$cmd' is required but not installed."
        exit 1
    fi
done

# ── Login check ─────────────────────────────────────────────
echo ""
echo "[*] Checking Azure login..."
if ! az account show &>/dev/null; then
    echo "[*] Not logged in — launching az login..."
    az login
fi
echo "[OK] Authenticated"

# ── Get subscriptions ───────────────────────────────────────
if [[ -z "$SUBSCRIPTIONS" ]]; then
    mapfile -t SUB_IDS < <(az account list --query "[?state=='Enabled'].id" -o tsv)
else
    read -ra SUB_IDS <<< "$SUBSCRIPTIONS"
fi
echo "[*] Scanning ${#SUB_IDS[@]} subscription(s)"

# ── Initialize JSON collectors ──────────────────────────────
VMS_JSON="[]"
DISKS_JSON="[]"
VNETS_JSON="[]"
NSGS_JSON="[]"
PIPS_JSON="[]"
SA_JSON="[]"
APPS_JSON="[]"
FUNCS_JSON="[]"
AVD_HP_JSON="[]"
AVD_SH_JSON="[]"
AVD_AG_JSON="[]"

# ── Loop subscriptions ──────────────────────────────────────
for SUB_ID in "${SUB_IDS[@]}"; do
    SUB_NAME=$(az account show --subscription "$SUB_ID" --query "name" -o tsv 2>/dev/null || echo "$SUB_ID")
    echo ""
    echo "[SUB] $SUB_NAME ($SUB_ID)"
    az account set --subscription "$SUB_ID"

    # ── VMs ─────────────────────────────────
    echo "  [+] VMs..."
    _vms=$(az vm list --show-details \
        --query "[].{Subscription:'$SUB_NAME',SubId:'$SUB_ID',Name:name,ResourceGroup:resourceGroup,Location:location,Size:hardwareProfile.vmSize,OSType:storageProfile.osDisk.osType,PowerState:powerState,ProvisionState:provisioningState}" \
        -o json 2>/dev/null || echo "[]")
    VMS_JSON=$(echo "$VMS_JSON $( echo "$_vms")" | jq -s '.[0] + .[1]')

    # ── Disks ────────────────────────────────
    echo "  [+] Disks..."
    _disks=$(az disk list \
        --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,SizeGB:diskSizeGb,SKU:sku.name,State:diskState,AttachedTo:managedBy,OSType:osType,EncryptionEnabled:encryptionSettingsCollection.enabled}" \
        -o json 2>/dev/null || echo "[]")
    DISKS_JSON=$(echo "$DISKS_JSON $_disks" | jq -s '.[0] + .[1]')

    # ── VNets ────────────────────────────────
    echo "  [+] VNets..."
    _vnets=$(az network vnet list \
        --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,AddressSpace:join(', ',addressSpace.addressPrefixes),SubnetCount:length(subnets),ProvisionState:provisioningState}" \
        -o json 2>/dev/null || echo "[]")
    VNETS_JSON=$(echo "$VNETS_JSON $_vnets" | jq -s '.[0] + .[1]')

    # ── NSGs ─────────────────────────────────
    echo "  [+] NSGs..."
    _nsgs=$(az network nsg list \
        --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,InboundRules:length(securityRules[?direction=='Inbound']),OutboundRules:length(securityRules[?direction=='Outbound']),ProvisionState:provisioningState}" \
        -o json 2>/dev/null || echo "[]")
    NSGS_JSON=$(echo "$NSGS_JSON $_nsgs" | jq -s '.[0] + .[1]')

    # ── Public IPs ───────────────────────────
    echo "  [+] Public IPs..."
    _pips=$(az network public-ip list \
        --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,IPAddress:ipAddress,AllocationMethod:publicIpAllocationMethod,SKU:sku.name,DNSLabel:dnsSettings.domainNameLabel,FQDN:dnsSettings.fqdn}" \
        -o json 2>/dev/null || echo "[]")
    PIPS_JSON=$(echo "$PIPS_JSON $_pips" | jq -s '.[0] + .[1]')

    # ── Storage ──────────────────────────────
    echo "  [+] Storage Accounts..."
    _sa=$(az storage account list \
        --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,Kind:kind,SKU:sku.name,AccessTier:accessTier,HTTPSOnly:enableHttpsTrafficOnly,AllowBlobPublic:allowBlobPublicAccess,TLSVersion:minimumTlsVersion,ProvisionState:provisioningState}" \
        -o json 2>/dev/null || echo "[]")
    SA_JSON=$(echo "$SA_JSON $_sa" | jq -s '.[0] + .[1]')

    # ── App Services ─────────────────────────
    echo "  [+] App Services..."
    _apps=$(az webapp list \
        --query "[?kind!='functionapp'].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,State:state,HostName:defaultHostName,Kind:kind,HTTPSOnly:httpsOnly}" \
        -o json 2>/dev/null || echo "[]")
    APPS_JSON=$(echo "$APPS_JSON $_apps" | jq -s '.[0] + .[1]')

    # ── Functions ────────────────────────────
    echo "  [+] Function Apps..."
    _funcs=$(az functionapp list \
        --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,State:state,HostName:defaultHostName,Kind:kind,HTTPSOnly:httpsOnly}" \
        -o json 2>/dev/null || echo "[]")
    FUNCS_JSON=$(echo "$FUNCS_JSON $_funcs" | jq -s '.[0] + .[1]')

    # ── AVD ──────────────────────────────────
    echo "  [+] AVD Resources..."

    # Ensure the desktopvirtualization extension is installed non-interactively
    if ! az extension show --name desktopvirtualization &>/dev/null; then
        echo "      [~] Installing desktopvirtualization extension..."
        az extension add --name desktopvirtualization --yes 2>/dev/null || true
    fi

    # Check if extension is now available; skip AVD if not
    if ! az extension show --name desktopvirtualization &>/dev/null; then
        echo "      [!] desktopvirtualization extension unavailable — skipping AVD"
    else
        # Host pools — 30s timeout to avoid hangs
        _hp=$(timeout 30 az desktopvirtualization hostpool list \
            --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,Type:hostPoolType,LoadBalancer:loadBalancerType,MaxSessions:maxSessionLimit,ValidationEnv:validationEnvironment}" \
            -o json 2>/dev/null || echo "[]")
        AVD_HP_JSON=$(echo "$AVD_HP_JSON $_hp" | jq -s '.[0] + .[1]')

        # App groups — 30s timeout
        _ag=$(timeout 30 az desktopvirtualization applicationgroup list \
            --query "[].{Subscription:'$SUB_NAME',Name:name,ResourceGroup:resourceGroup,Location:location,Type:applicationGroupType,Description:description}" \
            -o json 2>/dev/null || echo "[]")
        AVD_AG_JSON=$(echo "$AVD_AG_JSON $_ag" | jq -s '.[0] + .[1]')

        # Session hosts — iterate host pools safely, skip blanks
        _hp_count=$(echo "$_hp" | jq 'length' 2>/dev/null || echo 0)
        if [[ "$_hp_count" -gt 0 ]]; then
            while IFS=$'\t' read -r rg hpname; do
                # Skip empty lines that can come from jq on empty arrays
                [[ -z "$rg" || -z "$hpname" ]] && continue
                _sh=$(timeout 20 az desktopvirtualization sessionhost list \
                    --host-pool-name "$hpname" \
                    --resource-group "$rg" \
                    --query "[].{Subscription:'$SUB_NAME',Name:name,HostPool:'$hpname',Status:status,Sessions:session,AgentVersion:agentVersion,OSVersion:osVersion,AllowNewSession:allowNewSession}" \
                    -o json 2>/dev/null || echo "[]")
                AVD_SH_JSON=$(echo "$AVD_SH_JSON $_sh" | jq -s '.[0] + .[1]')
            done < <(echo "$_hp" | jq -r '.[] | [.ResourceGroup, .Name] | @tsv' 2>/dev/null)
        fi

        echo "      HP:$(echo "$_hp" | jq 'length' 2>/dev/null || echo 0) AG:$(echo "$_ag" | jq 'length' 2>/dev/null || echo 0) SH:$(echo "$AVD_SH_JSON" | jq 'length' 2>/dev/null || echo 0)"
    fi
done

# ── Counts ──────────────────────────────────────────────────
VM_COUNT=$(echo "$VMS_JSON"   | jq 'length')
DISK_COUNT=$(echo "$DISKS_JSON" | jq 'length')
VNET_COUNT=$(echo "$VNETS_JSON" | jq 'length')
NSG_COUNT=$(echo "$NSGS_JSON"   | jq 'length')
PIP_COUNT=$(echo "$PIPS_JSON"   | jq 'length')
SA_COUNT=$(echo "$SA_JSON"      | jq 'length')
APP_COUNT=$(echo "$APPS_JSON"   | jq 'length')
FUNC_COUNT=$(echo "$FUNCS_JSON" | jq 'length')
AVD_HP_COUNT=$(echo "$AVD_HP_JSON" | jq 'length')
AVD_SH_COUNT=$(echo "$AVD_SH_JSON" | jq 'length')
AVD_AG_COUNT=$(echo "$AVD_AG_JSON" | jq 'length')
TOTAL=$((VM_COUNT + DISK_COUNT + VNET_COUNT + NSG_COUNT + PIP_COUNT + SA_COUNT + APP_COUNT + FUNC_COUNT + AVD_HP_COUNT + AVD_SH_COUNT + AVD_AG_COUNT))

echo ""
echo "[*] Total resources: $TOTAL"

# ── Write JSON data file ─────────────────────────────────────
REPORT_DATE=$(date -u +"%Y%m%d-%H%M")
REPORT_FILE="$OUTPUT_DIR/Azure-Inventory-$REPORT_DATE.html"
JSON_FILE="$OUTPUT_DIR/azure-inventory-data-$REPORT_DATE.json"

jq -n \
  --argjson vms "$VMS_JSON" \
  --argjson disks "$DISKS_JSON" \
  --argjson vnets "$VNETS_JSON" \
  --argjson nsgs "$NSGS_JSON" \
  --argjson pips "$PIPS_JSON" \
  --argjson sa "$SA_JSON" \
  --argjson apps "$APPS_JSON" \
  --argjson funcs "$FUNCS_JSON" \
  --argjson avdhp "$AVD_HP_JSON" \
  --argjson avdsh "$AVD_SH_JSON" \
  --argjson avdag "$AVD_AG_JSON" \
  '{VMs:$vms,Disks:$disks,VNets:$vnets,NSGs:$nsgs,PublicIPs:$pips,StorageAccounts:$sa,AppServices:$apps,Functions:$funcs,AVDHostPools:$avdhp,AVDSessionHosts:$avdsh,AVDAppGroups:$avdag}' \
  > "$JSON_FILE"

echo "[OK] JSON data: $JSON_FILE"

# ── The HTML report template is embedded via the shared report-template.html ──
# If running standalone, the report will read the JSON file
# Alternatively, run with the PowerShell version for the full embedded report

# Quick summary to terminal
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        Azure Inventory Summary           ║"
echo "╠══════════════════════════════════════════╣"
printf "║  %-20s %20s ║\n" "Resource Type" "Count"
echo "╠══════════════════════════════════════════╣"
printf "║  %-30s %10s ║\n" "Virtual Machines"   "$VM_COUNT"
printf "║  %-30s %10s ║\n" "Managed Disks"      "$DISK_COUNT"
printf "║  %-30s %10s ║\n" "Virtual Networks"   "$VNET_COUNT"
printf "║  %-30s %10s ║\n" "Network Sec Groups" "$NSG_COUNT"
printf "║  %-30s %10s ║\n" "Public IP Addresses" "$PIP_COUNT"
printf "║  %-30s %10s ║\n" "Storage Accounts"   "$SA_COUNT"
printf "║  %-30s %10s ║\n" "App Services"       "$APP_COUNT"
printf "║  %-30s %10s ║\n" "Function Apps"      "$FUNC_COUNT"
printf "║  %-30s %10s ║\n" "AVD Host Pools"     "$AVD_HP_COUNT"
printf "║  %-30s %10s ║\n" "AVD Session Hosts"  "$AVD_SH_COUNT"
printf "║  %-30s %10s ║\n" "AVD App Groups"     "$AVD_AG_COUNT"
echo "╠══════════════════════════════════════════╣"
printf "║  %-30s %10s ║\n" "TOTAL" "$TOTAL"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "[OK] Data file: $JSON_FILE"
echo "[*]  Use report-template.html or Azure-Inventory.ps1 to generate the full HTML report"
echo ""
