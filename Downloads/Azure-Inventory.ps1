#Requires -Modules Az.Accounts, Az.Compute, Az.Network, Az.Storage, Az.Websites, Az.DesktopVirtualization
<#
.SYNOPSIS
    Azure Full Inventory Collector — Exports HTML Report
.DESCRIPTION
    Pulls VMs, Disks, Networking, Storage, App Services, Functions, and AVD/WVD
    resources across all subscriptions and generates a rich HTML report.
.PARAMETER SubscriptionIds
    Comma-separated list of Subscription IDs to scan. Defaults to ALL accessible subscriptions.
.PARAMETER OutputPath
    Where to save the HTML report. Defaults to current directory.
.PARAMETER TenantId
    Optional: Specify Tenant ID if you have multiple tenants.
.EXAMPLE
    .\Azure-Inventory.ps1
    .\Azure-Inventory.ps1 -SubscriptionIds "sub-id-1","sub-id-2" -OutputPath "C:\Reports"
#>

param(
    [string[]]$SubscriptionIds = @(),
    [string]$OutputPath = (Get-Location).Path,
    [string]$TenantId = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ─────────────────────────────────────────────
# CONNECT
# ─────────────────────────────────────────────
Write-Host "`n[*] Connecting to Azure..." -ForegroundColor Cyan
try {
    if ($TenantId) {
        Connect-AzAccount -TenantId $TenantId | Out-Null
    } else {
        $context = Get-AzContext
        if (-not $context) { Connect-AzAccount | Out-Null }
    }
} catch {
    Write-Error "Failed to connect to Azure: $_"
    exit 1
}

# ─────────────────────────────────────────────
# GET SUBSCRIPTIONS
# ─────────────────────────────────────────────
$allSubs = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
if ($SubscriptionIds.Count -gt 0) {
    $allSubs = $allSubs | Where-Object { $SubscriptionIds -contains $_.Id }
}
Write-Host "[*] Found $($allSubs.Count) subscription(s) to scan" -ForegroundColor Cyan

# ─────────────────────────────────────────────
# INVENTORY COLLECTIONS
# ─────────────────────────────────────────────
$inventory = @{
    VMs             = [System.Collections.Generic.List[hashtable]]::new()
    Disks           = [System.Collections.Generic.List[hashtable]]::new()
    VNets           = [System.Collections.Generic.List[hashtable]]::new()
    NSGs            = [System.Collections.Generic.List[hashtable]]::new()
    PublicIPs       = [System.Collections.Generic.List[hashtable]]::new()
    StorageAccounts = [System.Collections.Generic.List[hashtable]]::new()
    AppServices     = [System.Collections.Generic.List[hashtable]]::new()
    Functions       = [System.Collections.Generic.List[hashtable]]::new()
    AVDHostPools    = [System.Collections.Generic.List[hashtable]]::new()
    AVDSessionHosts = [System.Collections.Generic.List[hashtable]]::new()
    AVDAppGroups    = [System.Collections.Generic.List[hashtable]]::new()
}
$scanTime = Get-Date

foreach ($sub in $allSubs) {
    Write-Host "`n[SUB] $($sub.Name) ($($sub.Id))" -ForegroundColor Yellow
    Set-AzContext -SubscriptionId $sub.Id | Out-Null

    # ── VMs ──────────────────────────────────
    Write-Host "  [+] VMs..." -NoNewline
    $vms = Get-AzVM -Status
    foreach ($vm in $vms) {
        $inventory.VMs.Add(@{
            Subscription   = $sub.Name
            SubId          = $sub.Id
            Name           = $vm.Name
            ResourceGroup  = $vm.ResourceGroupName
            Location       = $vm.Location
            Size           = $vm.HardwareProfile.VmSize
            OSType         = $vm.StorageProfile.OsDisk.OsType
            OSImage        = "$($vm.StorageProfile.ImageReference.Publisher)/$($vm.StorageProfile.ImageReference.Offer)/$($vm.StorageProfile.ImageReference.Sku)"
            PowerState     = ($vm.Statuses | Where-Object { $_.Code -like "PowerState/*" } | Select-Object -First 1).DisplayStatus
            ProvisionState = $vm.ProvisioningState
            Tags           = ($vm.Tags | ConvertTo-Json -Compress)
        })
    }
    Write-Host " $($vms.Count)" -ForegroundColor Green

    # ── DISKS ────────────────────────────────
    Write-Host "  [+] Disks..." -NoNewline
    $disks = Get-AzDisk
    foreach ($disk in $disks) {
        $inventory.Disks.Add(@{
            Subscription  = $sub.Name
            Name          = $disk.Name
            ResourceGroup = $disk.ResourceGroupName
            Location      = $disk.Location
            SizeGB        = $disk.DiskSizeGB
            SKU           = $disk.Sku.Name
            State         = $disk.DiskState
            AttachedTo    = if ($disk.ManagedBy) { ($disk.ManagedBy -split '/')[-1] } else { "Unattached" }
            OSType        = $disk.OsType
            Encryption    = $disk.EncryptionSettingsCollection.Enabled
        })
    }
    Write-Host " $($disks.Count)" -ForegroundColor Green

    # ── VNETs ────────────────────────────────
    Write-Host "  [+] VNets..." -NoNewline
    $vnets = Get-AzVirtualNetwork
    foreach ($vnet in $vnets) {
        $inventory.VNets.Add(@{
            Subscription   = $sub.Name
            Name           = $vnet.Name
            ResourceGroup  = $vnet.ResourceGroupName
            Location       = $vnet.Location
            AddressSpace   = ($vnet.AddressSpace.AddressPrefixes -join ", ")
            SubnetCount    = $vnet.Subnets.Count
            Subnets        = ($vnet.Subnets | ForEach-Object { "$($_.Name): $($_.AddressPrefix)" }) -join " | "
            DNSServers     = ($vnet.DhcpOptions.DnsServers -join ", ")
            PeeringCount   = $vnet.VirtualNetworkPeerings.Count
            ProvisionState = $vnet.ProvisioningState
        })
    }
    Write-Host " $($vnets.Count)" -ForegroundColor Green

    # ── NSGs ─────────────────────────────────
    Write-Host "  [+] NSGs..." -NoNewline
    $nsgs = Get-AzNetworkSecurityGroup
    foreach ($nsg in $nsgs) {
        $inbound  = $nsg.SecurityRules | Where-Object { $_.Direction -eq "Inbound" }
        $outbound = $nsg.SecurityRules | Where-Object { $_.Direction -eq "Outbound" }
        $inventory.NSGs.Add(@{
            Subscription    = $sub.Name
            Name            = $nsg.Name
            ResourceGroup   = $nsg.ResourceGroupName
            Location        = $nsg.Location
            InboundRules    = $inbound.Count
            OutboundRules   = $outbound.Count
            AssociatedTo    = (($nsg.Subnets | ForEach-Object { ($_.Id -split '/')[-1] }) + ($nsg.NetworkInterfaces | ForEach-Object { ($_.Id -split '/')[-1] })) -join ", "
            ProvisionState  = $nsg.ProvisioningState
        })
    }
    Write-Host " $($nsgs.Count)" -ForegroundColor Green

    # ── PUBLIC IPs ───────────────────────────
    Write-Host "  [+] Public IPs..." -NoNewline
    $pips = Get-AzPublicIpAddress
    foreach ($pip in $pips) {
        $inventory.PublicIPs.Add(@{
            Subscription   = $sub.Name
            Name           = $pip.Name
            ResourceGroup  = $pip.ResourceGroupName
            Location       = $pip.Location
            IPAddress      = $pip.IpAddress
            AllocationMethod = $pip.PublicIpAllocationMethod
            SKU            = $pip.Sku.Name
            AssociatedTo   = if ($pip.IpConfiguration) { ($pip.IpConfiguration.Id -split '/')[-3] } else { "Unassociated" }
            DNSLabel       = $pip.DnsSettings.DomainNameLabel
            FQDN           = $pip.DnsSettings.Fqdn
        })
    }
    Write-Host " $($pips.Count)" -ForegroundColor Green

    # ── STORAGE ──────────────────────────────
    Write-Host "  [+] Storage Accounts..." -NoNewline
    $storageAccounts = Get-AzStorageAccount
    foreach ($sa in $storageAccounts) {
        $inventory.StorageAccounts.Add(@{
            Subscription    = $sub.Name
            Name            = $sa.StorageAccountName
            ResourceGroup   = $sa.ResourceGroupName
            Location        = $sa.Location
            Kind            = $sa.Kind
            SKU             = $sa.Sku.Name
            AccessTier      = $sa.AccessTier
            HTTPSOnly       = $sa.EnableHttpsTrafficOnly
            AllowBlobPublic = $sa.AllowBlobPublicAccess
            TLSVersion      = $sa.MinimumTlsVersion
            ProvisionState  = $sa.ProvisioningState
            Tags            = ($sa.Tags | ConvertTo-Json -Compress)
        })
    }
    Write-Host " $($storageAccounts.Count)" -ForegroundColor Green

    # ── APP SERVICES & FUNCTIONS ─────────────
    Write-Host "  [+] App Services / Functions..." -NoNewline
    $webApps = Get-AzWebApp
    foreach ($app in $webApps) {
        $entry = @{
            Subscription  = $sub.Name
            Name          = $app.Name
            ResourceGroup = $app.ResourceGroupName
            Location      = $app.Location
            State         = $app.State
            HostName      = ($app.HostNames -join ", ")
            AppServicePlan= $app.ServerFarmId ? ($app.ServerFarmId -split '/')[-1] : "N/A"
            Runtime       = "$($app.SiteConfig.LinuxFxVersion)$($app.SiteConfig.WindowsFxVersion)"
            HTTPSOnly     = $app.HttpsOnly
            Kind          = $app.Kind
        }
        if ($app.Kind -like "*functionapp*") {
            $inventory.Functions.Add($entry)
        } else {
            $inventory.AppServices.Add($entry)
        }
    }
    Write-Host " $($webApps.Count)" -ForegroundColor Green

    # ── AVD / WVD ────────────────────────────
    Write-Host "  [+] AVD Resources..." -NoNewline
    try {
        $hostPools = Get-AzWvdHostPool -ErrorAction SilentlyContinue
        foreach ($hp in $hostPools) {
            $inventory.AVDHostPools.Add(@{
                Subscription    = $sub.Name
                Name            = $hp.Name
                ResourceGroup   = $hp.Id.Split('/')[4]
                Location        = $hp.Location
                Type            = $hp.HostPoolType
                LoadBalancer    = $hp.LoadBalancerType
                MaxSessions     = $hp.MaxSessionLimit
                ValidationEnv   = $hp.ValidationEnvironment
                StartVMOnConnect= $hp.StartVMOnConnect
                CustomRdpProps  = $hp.CustomRdpProperty
            })
        }

        $sessionHosts = Get-AzWvdSessionHost -ErrorAction SilentlyContinue
        foreach ($sh in $sessionHosts) {
            $hpName = ($sh.Id -split '/')[10]
            $rg     = ($sh.Id -split '/')[4]
            $inventory.AVDSessionHosts.Add(@{
                Subscription  = $sub.Name
                Name          = $sh.Name.Split('/')[1]
                HostPool      = $hpName
                ResourceGroup = $rg
                Status        = $sh.Status
                Sessions      = $sh.Session
                AgentVersion  = $sh.AgentVersion
                OSVersion     = $sh.OsVersion
                LastHeartbeat = $sh.LastHeartBeat
                AllowNewSession = $sh.AllowNewSession
            })
        }

        $appGroups = Get-AzWvdApplicationGroup -ErrorAction SilentlyContinue
        foreach ($ag in $appGroups) {
            $inventory.AVDAppGroups.Add(@{
                Subscription  = $sub.Name
                Name          = $ag.Name
                ResourceGroup = $ag.Id.Split('/')[4]
                Location      = $ag.Location
                Type          = $ag.ApplicationGroupType
                HostPool      = ($ag.HostPoolArmPath -split '/')[-1]
                Description   = $ag.Description
            })
        }
        Write-Host " HP:$($hostPools.Count) SH:$($inventory.AVDSessionHosts.Count) AG:$($appGroups.Count)" -ForegroundColor Green
    } catch {
        Write-Host " (AVD module not available or no AVD resources)" -ForegroundColor DarkYellow
    }
}

# ─────────────────────────────────────────────
# GENERATE HTML REPORT
# ─────────────────────────────────────────────
Write-Host "`n[*] Generating HTML report..." -ForegroundColor Cyan

$totalResources = $inventory.VMs.Count + $inventory.Disks.Count + $inventory.VNets.Count +
                  $inventory.NSGs.Count + $inventory.PublicIPs.Count + $inventory.StorageAccounts.Count +
                  $inventory.AppServices.Count + $inventory.Functions.Count +
                  $inventory.AVDHostPools.Count + $inventory.AVDSessionHosts.Count + $inventory.AVDAppGroups.Count

function ConvertTo-HtmlTable {
    param([System.Collections.Generic.List[hashtable]]$Data, [string]$EmptyMessage = "No resources found")
    if ($Data.Count -eq 0) { return "<p class='empty'>$EmptyMessage</p>" }
    $keys = $Data[0].Keys
    $html = "<div class='table-wrap'><table><thead><tr>"
    foreach ($k in $keys) { $html += "<th>$k</th>" }
    $html += "</tr></thead><tbody>"
    foreach ($row in $Data) {
        $html += "<tr>"
        foreach ($k in $keys) {
            $val = $row[$k]
            if ($null -eq $val) { $val = "" }
            $cls = ""
            if ($k -eq "PowerState" -or $k -eq "State" -or $k -eq "Status") {
                if ($val -match "running|Available|succeeded|Enabled") { $cls = " class='status-ok'" }
                elseif ($val -match "stopped|deallocated|Unavailable|Failed|Disabled") { $cls = " class='status-bad'" }
                else { $cls = " class='status-warn'" }
            }
            $html += "<td$cls>$([System.Web.HttpUtility]::HtmlEncode($val.ToString()))</td>"
        }
        $html += "</tr>"
    }
    $html += "</tbody></table></div>"
    return $html
}

Add-Type -AssemblyName System.Web

$vmTable      = ConvertTo-HtmlTable $inventory.VMs
$diskTable    = ConvertTo-HtmlTable $inventory.Disks
$vnetTable    = ConvertTo-HtmlTable $inventory.VNets
$nsgTable     = ConvertTo-HtmlTable $inventory.NSGs
$pipTable     = ConvertTo-HtmlTable $inventory.PublicIPs
$saTable      = ConvertTo-HtmlTable $inventory.StorageAccounts
$appTable     = ConvertTo-HtmlTable $inventory.AppServices
$funcTable    = ConvertTo-HtmlTable $inventory.Functions
$hpTable      = ConvertTo-HtmlTable $inventory.AVDHostPools
$shTable      = ConvertTo-HtmlTable $inventory.AVDSessionHosts
$agTable      = ConvertTo-HtmlTable $inventory.AVDAppGroups

$reportDate = $scanTime.ToString("yyyy-MM-dd HH:mm:ss UTC")
$reportFile = Join-Path $OutputPath "Azure-Inventory-$(Get-Date -Format 'yyyyMMdd-HHmm').html"

$htmlContent = Get-Content -Path "$PSScriptRoot\report-template.html" -Raw -ErrorAction SilentlyContinue
if (-not $htmlContent) {
    # Inline template fallback — see report-template.html for full version
    $htmlContent = "TEMPLATE_PLACEHOLDER"
}

# Export JSON for the HTML template to consume
$jsonData = $inventory | ConvertTo-Json -Depth 5 -Compress
$reportHtml = $htmlContent `
    -replace "%%REPORT_DATE%%", $reportDate `
    -replace "%%TOTAL_RESOURCES%%", $totalResources `
    -replace "%%SUB_COUNT%%", $allSubs.Count `
    -replace "%%VM_COUNT%%", $inventory.VMs.Count `
    -replace "%%DISK_COUNT%%", $inventory.Disks.Count `
    -replace "%%VNET_COUNT%%", $inventory.VNets.Count `
    -replace "%%NSG_COUNT%%", $inventory.NSGs.Count `
    -replace "%%PIP_COUNT%%", $inventory.PublicIPs.Count `
    -replace "%%SA_COUNT%%", $inventory.StorageAccounts.Count `
    -replace "%%APP_COUNT%%", $inventory.AppServices.Count `
    -replace "%%FUNC_COUNT%%", $inventory.Functions.Count `
    -replace "%%AVD_HP_COUNT%%", $inventory.AVDHostPools.Count `
    -replace "%%AVD_SH_COUNT%%", $inventory.AVDSessionHosts.Count `
    -replace "%%AVD_AG_COUNT%%", $inventory.AVDAppGroups.Count `
    -replace "%%VM_TABLE%%", $vmTable `
    -replace "%%DISK_TABLE%%", $diskTable `
    -replace "%%VNET_TABLE%%", $vnetTable `
    -replace "%%NSG_TABLE%%", $nsgTable `
    -replace "%%PIP_TABLE%%", $pipTable `
    -replace "%%SA_TABLE%%", $saTable `
    -replace "%%APP_TABLE%%", $appTable `
    -replace "%%FUNC_TABLE%%", $funcTable `
    -replace "%%AVD_HP_TABLE%%", $hpTable `
    -replace "%%AVD_SH_TABLE%%", $shTable `
    -replace "%%AVD_AG_TABLE%%", $agTable

$reportHtml | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "[OK] Report saved: $reportFile" -ForegroundColor Green
Write-Host "[*] Total resources collected: $totalResources`n" -ForegroundColor Cyan

# Open report automatically on Windows
if ($IsWindows -or $env:OS -eq "Windows_NT") {
    Start-Process $reportFile
}
