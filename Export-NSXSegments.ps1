#Requires -Version 5.1
<#
.SYNOPSIS
    Exports NSX segments, custom segment profiles, and profile bindings to a
    JSON + CSV file pair for use with Import-NSXSegments.ps1.

.DESCRIPTION
    Connects to the source NSX Manager and produces two files:

      <OutputBase>.json  - All exported objects (segments, profiles, bindings).
                           This file is the input to Import-NSXSegments.ps1.

      <OutputBase>.csv   - Name-mapping table, pre-filled with OldName = NewName.
                           Edit the NewName column for any object you want renamed
                           on the target NSX, then leave all others unchanged.

    After connecting, an interactive menu lets you choose which segments to
    export. Only the profiles and bindings referenced by your selection are
    included in the output.

    NSX version compatibility
    -------------------------
    NSX 4.x stores profiles under  /infra/segment-profiles/<type>/
    NSX 9.x stores profiles under  /infra/<type>/
    Both formats are tried automatically.

    Profile binding maps (the link between a segment and its custom profiles)
    are stored as typed child resources of the segment:
      segment-discovery-profile-binding-maps  (IP Discovery, MAC Discovery)
      segment-security-profile-binding-maps   (Segment Security, SpoofGuard)
      segment-qos-profile-binding-maps        (QoS)

.PARAMETER NSXManager
    FQDN or IP address of the source NSX Manager.

.PARAMETER Credential
    PSCredential for the NSX Manager admin account. Prompted if omitted.

.PARAMETER OutputBase
    Base path (without extension) for the output files.
    Defaults to ./nsx-export_<timestamp>.
    Produces: <OutputBase>.json and <OutputBase>.csv

.PARAMETER SegmentFilter
    Wildcard applied to segment display_name before the selection menu appears.
    Default: '*' (show all segments).

.PARAMETER SkipCertCheck
    Bypass TLS certificate validation. Use for self-signed certificates.

.EXAMPLE
    .\Export-NSXSegments.ps1 -NSXManager nsx.corp.local -SkipCertCheck

.EXAMPLE
    .\Export-NSXSegments.ps1 -NSXManager nsx.corp.local `
        -OutputBase ./exports/prod-migration `
        -SegmentFilter "prod-*" `
        -SkipCertCheck

.OUTPUTS
    <OutputBase>.json  - Segment + profile data consumed by Import-NSXSegments.ps1
    <OutputBase>.csv   - Name-mapping table; edit NewName column before importing

.NOTES
    Version : 2.0
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Pair    : Import-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$NSXManager,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputBase = ("./nsx-export_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')),

    [string]$SegmentFilter = '*',

    [switch]$SkipCertCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

function Get-BasicAuthHeader {
    param([System.Management.Automation.PSCredential]$Cred)
    $pair    = "$($Cred.UserName):$($Cred.GetNetworkCredential().Password)"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    return @{ Authorization = "Basic $encoded"; 'Content-Type' = 'application/json' }
}

function Set-TlsSkipCert {
    # ServicePointManager requires a compiled .NET delegate in PS5 / .NET 4.x.
    # A PowerShell scriptblock assigned to the callback is silently ignored there.
    if (-not ([System.Management.Automation.PSTypeName]'CertIgnore').Type) {
        Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class CertIgnore {
    public static void Disable() {
        ServicePointManager.ServerCertificateValidationCallback =
            (RemoteCertificateValidationCallback) delegate { return true; };
        ServicePointManager.SecurityProtocol =
            SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
    }
}
"@
    }
    [CertIgnore]::Disable()
}

function Invoke-NSXApi {
    # Issues a REST call to the NSX Manager and returns the parsed JSON response.
    # Throws on any non-2xx HTTP status so callers can use try/catch.
    param([string]$Path, [string]$Method = 'GET')
    $params = @{
        Uri             = "https://$NSXManager$Path"
        Method          = $Method
        Headers         = $script:Headers
        UseBasicParsing = $true
    }
    if ($SkipCertCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
        $params['SkipCertificateCheck'] = $true
    }
    try {
        $response = Invoke-WebRequest @params
        if ($response.Content) { return ($response.Content | ConvertFrom-Json) }
    } catch {
        $code = if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $_.Exception.Response.StatusCode.value__
        } else { 'N/A' }
        Write-Warning "  API error [$Method $Path] -> HTTP $code : $_"
        throw
    }
}

function Get-AllPages {
    # Iterates cursor-based pagination and returns all results as a flat array.
    param([string]$Path)
    $results = @()
    $cursor  = $null
    do {
        $sep  = if ($Path -match '\?') { '&' } else { '?' }
        $page = if ($cursor) {
            Invoke-NSXApi -Path "$Path${sep}cursor=$cursor"
        } else {
            Invoke-NSXApi -Path $Path
        }
        if ($page.PSObject.Properties['results'] -and $page.results) {
            $results += $page.results
        }
        $cursor = if ($page.PSObject.Properties['cursor']) { $page.cursor } else { $null }
    } while ($cursor)
    return $results
}

function Select-Segments {
    # Presents a numbered list and returns the segments chosen by the operator.
    # Accepts: individual numbers, comma-separated numbers, ranges (e.g. 1-5),
    # or * for all.
    param([array]$Segments)

    $sorted = @($Segments | Sort-Object display_name)
    $total  = $sorted.Count

    Write-Host ""
    Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "|  SELECT SEGMENTS TO EXPORT                       |" -ForegroundColor Yellow
    Write-Host "|  Numbers, ranges (1-5), * for all, or a mix.    |" -ForegroundColor Yellow
    Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""

    for ($i = 0; $i -lt $total; $i++) {
        $seg  = $sorted[$i]
        $num  = ($i + 1).ToString().PadLeft($total.ToString().Length)
        $vlan = if ($seg.PSObject.Properties['vlan_ids'] -and $seg.vlan_ids) {
                    "VLAN $($seg.vlan_ids -join ',')"
                } else { 'overlay' }
        $t1   = if ($seg.PSObject.Properties['connectivity_path'] -and
                    $seg.connectivity_path -and
                    $seg.connectivity_path -match '/tier-1s/([^/]+)') {
                    "T1:$($Matches[1])"
                } else { '' }
        $meta = @($vlan, $t1) | Where-Object { $_ }
        $hint = if ($meta) { "  [$($meta -join '  ')]" } else { '' }
        Write-Host ("  [{0}] {1}{2}" -f $num, $seg.display_name, $hint)
    }

    Write-Host ""

    $selected = $null
    while (-not $selected) {
        $raw = (Read-Host "  Select").Trim()

        if ($raw -eq '*') { $selected = $sorted; break }

        $indices = [System.Collections.Generic.HashSet[int]]::new()
        $valid   = $true

        foreach ($token in ($raw -split ',')) {
            $token = $token.Trim()
            if ($token -match '^(\d+)-(\d+)$') {
                $from = [int]$Matches[1]; $to = [int]$Matches[2]
                if ($from -lt 1 -or $to -gt $total -or $from -gt $to) {
                    Write-Host "  Invalid range '$token' - valid range is 1-$total" -ForegroundColor Red
                    $valid = $false; break
                }
                $from..$to | ForEach-Object { $indices.Add($_) | Out-Null }
            } elseif ($token -match '^\d+$') {
                $n = [int]$token
                if ($n -lt 1 -or $n -gt $total) {
                    Write-Host "  Invalid number '$token' - valid range is 1-$total" -ForegroundColor Red
                    $valid = $false; break
                }
                $indices.Add($n) | Out-Null
            } else {
                Write-Host "  Cannot parse '$token'" -ForegroundColor Red
                $valid = $false; break
            }
        }

        if ($valid -and $indices.Count -gt 0) {
            $selected = @($indices | Sort-Object | ForEach-Object { $sorted[$_ - 1] })
        } elseif ($valid) {
            Write-Host "  Nothing selected - enter at least one number" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  Selected $($selected.Count) of $total segment(s):" -ForegroundColor Green
    $selected | ForEach-Object { Write-Host "    - $($_.display_name)" }
    Write-Host ""
    return @($selected)
}

# =============================================================================
#  MAIN
# =============================================================================

Write-Host @"
+==================================================+
|   Export-NSXSegments.ps1  v2.0                   |
|   Compatible with NSX 4.x and 9.x                |
+==================================================+
"@ -ForegroundColor Cyan

$jsonPath = "$OutputBase.json"
$csvPath  = "$OutputBase.csv"

if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter credentials for NSX Manager ($NSXManager)"
}
if ($SkipCertCheck -and $PSVersionTable.PSVersion.Major -lt 6) { Set-TlsSkipCert }
$script:Headers = Get-BasicAuthHeader -Cred $Credential

# -- 1. Verify connectivity ---------------------------------------------------
Write-Host "`n[1/5] Verifying connectivity to $NSXManager ..." -ForegroundColor Cyan
$ver = Invoke-NSXApi -Path '/api/v1/node/version'
Write-Host "      NSX version : $($ver.product_version)" -ForegroundColor Green

# -- 2. Fetch segments and interactive selection ------------------------------
Write-Host "`n[2/5] Fetching segments (filter: '$SegmentFilter') ..." -ForegroundColor Cyan
$allSegments = @(Get-AllPages -Path '/policy/api/v1/infra/segments')
$filtered    = @($allSegments | Where-Object { $_.display_name -like $SegmentFilter })
Write-Host "      Found $($filtered.Count) segment(s) matching filter out of $($allSegments.Count) total"

if ($filtered.Count -eq 0) {
    Write-Warning "No segments matched '$SegmentFilter'. Nothing to export."
    exit 0
}

$segments = @(Select-Segments -Segments $filtered)

if ($segments.Count -eq 0) {
    Write-Warning "No segments selected. Nothing to export."
    exit 0
}

# -- 3. Collect custom segment profiles --------------------------------------
# NSX 4.x path: /infra/segment-profiles/<type>/
# NSX 9.x path: /infra/<type>/
# Both are tried for each profile type; the first that responds is used.
Write-Host "`n[3/5] Collecting custom segment profiles ..." -ForegroundColor Cyan

$profileTypes = [ordered]@{
    'qos-profiles'              = @("/policy/api/v1/infra/qos-profiles",
                                    "/policy/api/v1/infra/segment-profiles/qos-profiles")
    'spoofguard-profiles'       = @("/policy/api/v1/infra/spoofguard-profiles",
                                    "/policy/api/v1/infra/segment-profiles/spoofguard-profiles")
    'ip-discovery-profiles'     = @("/policy/api/v1/infra/ip-discovery-profiles",
                                    "/policy/api/v1/infra/segment-profiles/ip-discovery-profiles")
    'mac-discovery-profiles'    = @("/policy/api/v1/infra/mac-discovery-profiles",
                                    "/policy/api/v1/infra/segment-profiles/mac-discovery-profiles")
    'segment-security-profiles' = @("/policy/api/v1/infra/segment-security-profiles",
                                    "/policy/api/v1/infra/segment-profiles/segment-security-profiles")
}

$customProfiles = [ordered]@{}

foreach ($ptype in $profileTypes.Keys) {
    $profiles = $null
    foreach ($apiPath in $profileTypes[$ptype]) {
        try {
            $profiles = Get-AllPages -Path $apiPath
            Write-Verbose "      [$ptype] resolved via $apiPath"
            break
        } catch {
            Write-Verbose "      [$ptype] not available at $apiPath"
        }
    }
    if (-not $profiles) {
        Write-Warning "      [$ptype] could not be retrieved from any known path - skipping"
        continue
    }
    # Exclude built-in default profiles; only capture custom ones
    foreach ($p in ($profiles | Where-Object {
            $_.PSObject.Properties['path'] -and
            $_.path -notmatch '/default-' -and
            $_.PSObject.Properties['display_name'] -and
            $_.display_name -notmatch '^default' })) {
        $customProfiles[$p.path] = $p
        Write-Host "      [$ptype] $($p.display_name)"
    }
}

Write-Host "      Total custom profiles: $($customProfiles.Count)"

# -- 4. Fetch profile binding maps and write JSON ----------------------------
# Profile bindings are stored as typed child resources under each segment.
# Three binding map types cover all five profile categories:
#   segment-discovery-profile-binding-maps  -> ip_discovery_profile_path,
#                                              mac_discovery_profile_path
#   segment-security-profile-binding-maps   -> segment_security_profile_path,
#                                              spoofguard_profile_path
#   segment-qos-profile-binding-maps        -> qos_profile_path
Write-Host "`n[4/5] Writing JSON export ..." -ForegroundColor Cyan
Write-Host "      Fetching profile binding maps ..."

$bindingMapTypes = @(
    'segment-discovery-profile-binding-maps',
    'segment-security-profile-binding-maps',
    'segment-qos-profile-binding-maps'
)

$bindingMaps = [ordered]@{}

foreach ($seg in $segments) {
    $segId      = $seg.id
    $segEntries = @()

    foreach ($bmType in $bindingMapTypes) {
        try {
            $maps = @(Get-AllPages -Path "/policy/api/v1/infra/segments/$segId/$bmType")
            # Only keep binding maps that reference at least one non-default custom profile
            $custom = @($maps | Where-Object {
                $hasCustom = $false
                foreach ($prop in $_.PSObject.Properties) {
                    if ($prop.Name -match '_profile_path$' -and
                        $prop.Value -is [string] -and
                        $prop.Value -notmatch '/default-') {
                        $hasCustom = $true
                    }
                }
                $hasCustom
            })
            foreach ($bm in $custom) {
                $segEntries += [PSCustomObject]@{ bmtype = $bmType; data = $bm }
                $bmName = if ($bm.PSObject.Properties['display_name']) { $bm.display_name } else { $bm.id }
                Write-Host "      [binding] '$($seg.display_name)' /$bmType -> '$bmName'"
                foreach ($prop in $bm.PSObject.Properties) {
                    if ($prop.Name -match '_profile_path$' -and $prop.Value -is [string]) {
                        Write-Host "        $($prop.Name) = $($prop.Value)"
                    }
                }
            }
        } catch {
            Write-Verbose "      /$bmType not available for '$($seg.display_name)'"
        }
    }

    if ($segEntries.Count -gt 0) {
        $bindingMaps[$segId] = $segEntries
    } else {
        Write-Host "      [binding] '$($seg.display_name)' -> no custom profile bindings"
    }
}
Write-Host "      Segments with profile bindings: $($bindingMaps.Count)"

$export = [ordered]@{
    export_version       = '2.0'
    export_timestamp     = (Get-Date -Format 'o')
    source_manager       = $NSXManager
    source_version       = $ver.product_version
    segment_filter       = $SegmentFilter
    segments             = $segments
    segment_profiles     = @($customProfiles.Values)
    segment_binding_maps = $bindingMaps
}

$export | ConvertTo-Json -Depth 20 | Out-File -FilePath $jsonPath -Encoding utf8
$jsonSize = [math]::Round((Get-Item $jsonPath).Length / 1KB, 1)
Write-Host "      Written: $jsonPath (${jsonSize} KB)"

# -- 5. Write CSV name-mapping table -----------------------------------------
Write-Host "`n[5/5] Writing CSV name-mapping table ..." -ForegroundColor Cyan

$t1Ids = [System.Collections.Generic.HashSet[string]]::new()
foreach ($seg in $segments) {
    if ($seg.PSObject.Properties['connectivity_path'] -and
        $seg.connectivity_path -and
        $seg.connectivity_path -match '/tier-1s/([^/]+)') {
        $t1Ids.Add($Matches[1]) | Out-Null
    }
}

$csvRows = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($seg in @($segments | Sort-Object display_name)) {
    $vlan = if ($seg.PSObject.Properties['vlan_ids'] -and $seg.vlan_ids) {
                $seg.vlan_ids -join ','
            } else { '' }
    $tz   = if ($seg.PSObject.Properties['transport_zone_path'] -and $seg.transport_zone_path) {
                Split-Path $seg.transport_zone_path -Leaf
            } else { '' }
    $csvRows.Add([PSCustomObject]@{
        Type    = 'Segment'
        OldName = $seg.display_name
        NewName = $seg.display_name
        Notes   = "VLAN: $vlan  |  TZ: $tz"
    })
}

foreach ($p in @($customProfiles.Values | Sort-Object display_name)) {
    # Extract profile type from path - works for both NSX 4 and NSX 9 path formats
    $ptype = if ($p.path -match '/([^/]+-profiles)/[^/]+$') { $Matches[1] } else { 'unknown' }
    $csvRows.Add([PSCustomObject]@{
        Type    = 'SegmentProfile'
        OldName = $p.display_name
        NewName = $p.display_name
        Notes   = $ptype
    })
}

foreach ($t1 in @($t1Ids | Sort-Object)) {
    $csvRows.Add([PSCustomObject]@{
        Type    = 'T1Gateway'
        OldName = $t1
        NewName = $t1
        Notes   = 'Edit NewName if this T1 gateway has a different id on the target NSX'
    })
}

$csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
Write-Host "      Written: $csvPath ($($csvRows.Count) rows)"

# -- Summary ------------------------------------------------------------------
Write-Host @"

+==================================================+
|   EXPORT COMPLETE                                |
+==================================================+
|  Segments exported  : $($segments.Count.ToString().PadRight(26))|
|  Profiles exported  : $($customProfiles.Count.ToString().PadRight(26))|
|  T1 Gateways found  : $($t1Ids.Count.ToString().PadRight(26))|
|  JSON               : $($jsonPath.PadRight(26))|
|  CSV (edit me!)     : $($csvPath.PadRight(26))|
+==================================================+

Next steps:
  1. Edit the NewName column in: $csvPath
     Leave NewName = OldName for objects that should keep their existing name.
  2. Run:
     .\Import-NSXSegments.ps1 -NSXManager <target> -InputPath '$jsonPath'
"@ -ForegroundColor Green
