#Requires -Version 5.1

<#
.SYNOPSIS
    Exports NSX segments, custom segment profiles, and profile binding maps
    to a JSON + CSV file pair for use with Import-NSXSegments.ps1.

.DESCRIPTION
    Connects to the source NSX Manager and produces two files:

      <OutputBase>.json  - All exported objects consumed by Import-NSXSegments.ps1.
      <OutputBase>.csv   - Name-mapping table. Edit the NewName column for any
                           object you want renamed on the target NSX. Leave
                           NewName = OldName to keep the existing name.

    An interactive menu lets you select exactly which segments to export.
    All custom profiles and binding maps referenced by the selection are
    included automatically.

    Credentials
    -----------
    On first run you are prompted for username and password, then asked whether
    to save them for future runs. Saved credentials are stored per NSX Manager
    in <manager>.cred next to the scripts (encrypted with DPAPI on
    Windows, not encrypted on Linux and macOS). On
    subsequent runs a menu offers to reuse, overwrite, or ignore the saved
    credential. Pass -Credential to bypass the interactive flow entirely.

    NSX version compatibility
    -------------------------
    NSX 4.x stores profiles under  /infra/segment-profiles/<type>/
    NSX 9.x stores profiles under  /infra/<type>/
    Both formats are tried automatically; the first that responds is used.

    Profile binding map types
    -------------------------
    segment-discovery-profile-binding-maps  (IP Discovery, MAC Discovery)
    segment-security-profile-binding-maps   (Segment Security, SpoofGuard)
    segment-qos-profile-binding-maps        (QoS)

.PARAMETER NSXManager
    FQDN or IP address of the source NSX Manager. If omitted, the script asks
    for it and lists the managers with a saved credential.

.PARAMETER Credential
    PSCredential for the NSX Manager admin account.
    If omitted, the built-in credential manager handles prompting and saving.

.PARAMETER OutputBase
    Base path (without extension) for the output files.
    Defaults to ./nsx-export_<timestamp>.
    Produces: <OutputBase>.json and <OutputBase>.csv

.PARAMETER SegmentFilter
    Wildcard applied to segment display_name before the selection menu appears.
    Default: '*' (show all segments).

.PARAMETER NoSearch
    Read the profile binding maps per segment (three GETs per segment) instead
    of with the NSX search API (three calls in total). Use it when the search
    API is unavailable or to rule out a lagging search index; the script also
    falls back to this by itself when a search call fails.

.PARAMETER SkipCertCheck
    Bypass TLS certificate validation. Use for self-signed certificates.
    For internal CA certificates, import the CA root into the Windows Trusted
    Root store instead: Import-Certificate -FilePath ca.cer
    -CertStoreLocation Cert:\LocalMachine\Root

.EXAMPLE
    .\Export-NSXSegments.ps1 -NSXManager nsx.corp.local -SkipCertCheck

.EXAMPLE
    .\Export-NSXSegments.ps1 -NSXManager nsx.corp.local `
        -SegmentFilter "prod-*" `
        -OutputBase ./exports/prod-migration `
        -SkipCertCheck

.OUTPUTS
    <OutputBase>.json  - Object data consumed by Import-NSXSegments.ps1
    <OutputBase>.csv   - Name-mapping table; edit NewName column before importing

.NOTES
    Version : 2.6
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Pair    : Import-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
    GitHub  : https://github.com/pauldiee/nsx-segment-migration

    Exit codes: 0 export written or nothing to export, 1 fatal error.

    Changelog
    ---------
    2.6 - Interactive start (#20): without -NSXManager the script asks for
          it (managers with a saved credential as numbers). The summary box
          fits its content and shows full paths; then the next command and,
          on Windows, an offer to open the CSV.
          The real error as one red ERROR: line instead of a PowerShell
          error record. An untrusted certificate without -SkipCertCheck:
          asks whether to go on without the check for this run. Saved
          credentials as <manager>.cred next to the scripts, as in the
          vCenter toolkits (creds\ and the profile file are still read).
          Needs NSXSM-Common.ps1 1.2.
    2.5 - Shared helpers moved to NSXSM-Common.ps1 (#11), unchanged: REST
          calls, pickers, prompts and credentials. The script stops with a
          clear message when NSXSM-Common.ps1 is missing or older than 1.0;
          the banner shows its version. Commands and parameters are the same.
          Help: credentials are in creds\ next to the scripts (since #3),
          not in the user profile.
    2.4 - Scale (#10): profile binding maps via the NSX search API (three
          calls instead of three per segment), with -NoSearch and an
          automatic fallback to per-segment GETs. Running count when reading
          per segment, quieter console. API errors show NSX's error_message.
          Get-AllPages no longer grows an array with +=.
          Segment picker as in VIFolderManager/VITagManager: filter on the
          whole line (wildcard or /text: /VLAN, /T1:<name>, /TZ:<name>),
          'reset', 'list', 'all', 'cancel'; long lists are shortened.
    2.3 - Get-Help shows the full help again: blank line between
          #Requires and the help block (without it Get-Help ignored
          the whole help block).
    2.2 - Prompts without console input stop with a clear message instead
          of failing on .Trim() of $null. Credentials are saved in
          creds\<manager>.cred next to the script; the old file in the user
          profile is still read (#3).
    2.1 - Added built-in credential save/reset via Resolve-Credential.
          Replaced Get-Credential with Read-Host to fix null credential errors
          in non-interactive PowerShell hosts under Set-StrictMode.
          Added $ScriptMeta branding banner (Name, Author, Blog, Date).
    2.0 - Full rewrite. Clean comments, consistent style.
          Profile binding maps exported via typed child paths.
          NSX 4.x and 9.x profile path formats handled automatically.
          Cursor-based pagination via Get-AllPages.
    1.x - Initial versions. Interactive segment selection menu.
          CSV name-mapping table. JSON export format.
#>

[CmdletBinding()]
param(
    [string]$NSXManager,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputBase = ("./nsx-export_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')),

    [string]$SegmentFilter = '*',

    [switch]$NoSearch,

    [switch]$SkipCertCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Shared helpers (#11): REST calls, pickers, prompts and credentials live in
# NSXSM-Common.ps1. Keep it in the same folder as this script.
$commonPath = Join-Path $PSScriptRoot 'NSXSM-Common.ps1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host "NSXSM-Common.ps1 not found next to this script ($PSScriptRoot). Copy the whole folder, not just one script." -ForegroundColor Red
    exit 1
}
. $commonPath
if (-not (Test-Path Variable:NSXSMCommonVersion) -or [version]$NSXSMCommonVersion -lt [version]'1.2') {
    Write-Host "NSXSM-Common.ps1 next to this script is older than 1.2. Copy the whole folder of this release." -ForegroundColor Red
    exit 1
}

# A fatal error as one clear line instead of a PowerShell error record
# pointing into NSXSM-Common.ps1; exit code 1 as before
trap { Write-Host ''; Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

function Get-BindingMapsBySearch {
    # Reads every segment profile binding map with three search API calls (one
    # per type) instead of three GETs per segment (#10). Returns a hashtable:
    # segment path -> list of [pscustomobject]@{ bmtype; data }. Throws when the
    # search API is unavailable, so the caller can fall back to per-segment GETs.
    $typeMap = [ordered]@{
        'SegmentDiscoveryProfileBindingMap' = 'segment-discovery-profile-binding-maps'
        'SegmentSecurityProfileBindingMap'  = 'segment-security-profile-binding-maps'
        'SegmentQoSProfileBindingMap'       = 'segment-qos-profile-binding-maps'
    }
    $byParent = @{}
    foreach ($rt in $typeMap.Keys) {
        foreach ($bm in (Get-AllPages -Path "/policy/api/v1/search/query?query=resource_type:$rt")) {
            if (-not $bm.PSObject.Properties['parent_path']) { continue }
            if (-not $byParent.ContainsKey($bm.parent_path)) {
                $byParent[$bm.parent_path] = [System.Collections.Generic.List[object]]::new()
            }
            $byParent[$bm.parent_path].Add([pscustomobject]@{ bmtype = $typeMap[$rt]; data = $bm })
        }
    }
    return $byParent
}

function Select-Segments {
    # Segment picker (#10): see Select-FromList
    param([array]$Segments)
    return Select-FromList -Items $Segments -Title 'SELECT SEGMENTS TO EXPORT' -LineText { param($s) Get-SegmentLine -Seg $s }
}

# =============================================================================
#  SCRIPT METADATA
# =============================================================================

$ScriptMeta = @{
    Name    = "Export-NSXSegments.ps1"
    Version = "2.6"
    Author  = "Paul van Dieen"
    Blog    = "https://www.hollebollevsan.nl"
    Date    = "2026-11-27"
}

# =============================================================================
#  MAIN
# =============================================================================

$bannerWidth = 62
Write-Host ""
Write-Host ("=" * $bannerWidth) -ForegroundColor DarkCyan
Write-Host ("  {0,-30} {1}" -f $ScriptMeta.Name, ("v" + $ScriptMeta.Version)) -ForegroundColor Cyan
Write-Host ("  Author : {0}" -f $ScriptMeta.Author) -ForegroundColor Cyan
Write-Host ("  Blog   : {0}" -f $ScriptMeta.Blog) -ForegroundColor Cyan
Write-Host ("  Date   : {0}" -f $ScriptMeta.Date) -ForegroundColor DarkGray
Write-Host ("  Common : v{0}" -f $NSXSMCommonVersion) -ForegroundColor DarkGray
Write-Host ("=" * $bannerWidth) -ForegroundColor DarkCyan
Write-Host ""

# No -NSXManager: ask for it, with the managers that have a saved credential
if (-not $NSXManager) {
    $NSXManager = Read-NSXManager -Role 'SOURCE NSX MANAGER (export from)'
    if (-not $NSXManager) { Write-Host "  Nothing exported." -ForegroundColor Yellow; exit 0 }
}

$jsonPath = "$OutputBase.json"
$csvPath  = "$OutputBase.csv"

$Credential = Resolve-Credential -Supplied $Credential -Manager $NSXManager
if ($SkipCertCheck -and $PSVersionTable.PSVersion.Major -lt 6) { Set-TlsSkipCert }
$script:Headers = Get-BasicAuthHeader -Cred $Credential

# -- 1. Verify connectivity ---------------------------------------------------
Write-Host "`n[1/5] Verifying connectivity to $NSXManager ..." -ForegroundColor Cyan
$ver = Test-NSXConnection
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

$script:TzNames = Get-TransportZoneNames
$segments = @(Select-Segments -Segments $filtered)

if ($segments.Count -eq 0) {
    if ($script:PickerCancelled) { Write-Host "  Nothing exported." -ForegroundColor Yellow }
    else { Write-Warning "No segments selected. Nothing to export." }
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
            Write-Verbose "[$ptype] resolved via $apiPath"
            break
        } catch {
            Write-Verbose "[$ptype] not available at $apiPath"
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

function Test-CustomBinding {
    # True when a binding map references at least one non-default profile
    param($Bm)
    foreach ($prop in $Bm.PSObject.Properties) {
        if ($prop.Name -match '_profile_path$' -and $prop.Value -is [string] -and
            $prop.Value -notmatch '/default-') { return $true }
    }
    return $false
}

# Fast path: three search calls for all binding maps (#10). Falls back to the
# per-segment GETs when the search API fails or -NoSearch is given.
$searchMaps = $null
if (-not $NoSearch) {
    try {
        $searchMaps = Get-BindingMapsBySearch
        Write-Host "      Read via the search API"
    } catch {
        Write-Warning "      Search API not available ($_); reading per segment instead"
        $searchMaps = $null
    }
}

$segNo    = 0
$segTotal = $segments.Count
foreach ($seg in $segments) {
    $segNo++
    $segId      = $seg.id
    $segEntries = [System.Collections.Generic.List[object]]::new()

    if ($null -ne $searchMaps) {
        $segPath = if ($seg.PSObject.Properties['path']) { $seg.path } else { "/infra/segments/$segId" }
        if ($searchMaps.ContainsKey($segPath)) {
            foreach ($e in $searchMaps[$segPath]) {
                if (Test-CustomBinding -Bm $e.data) { $segEntries.Add($e) }
            }
        }
    } else {
        if ($segNo -eq 1 -or $segNo % 50 -eq 0 -or $segNo -eq $segTotal) {
            Write-Host "      [$segNo/$segTotal] reading binding maps ..."
        }
        Write-Progress -Activity 'Reading profile binding maps' -Status "$segNo of $segTotal" -PercentComplete ([int](100 * $segNo / $segTotal))
        foreach ($bmType in $bindingMapTypes) {
            try {
                foreach ($bm in (Get-AllPages -Path "/policy/api/v1/infra/segments/$segId/$bmType")) {
                    if (Test-CustomBinding -Bm $bm) { $segEntries.Add([PSCustomObject]@{ bmtype = $bmType; data = $bm }) }
                }
            } catch {
                Write-Verbose "/$bmType not available for '$($seg.display_name)'"
            }
        }
    }

    foreach ($e in $segEntries) {
        $bm     = $e.data
        $bmName = if ($bm.PSObject.Properties['display_name']) { $bm.display_name } else { $bm.id }
        Write-Host "      [binding] '$($seg.display_name)' /$($e.bmtype) -> '$bmName'"
        foreach ($prop in $bm.PSObject.Properties) {
            if ($prop.Name -match '_profile_path$' -and $prop.Value -is [string]) {
                Write-Verbose "        $($prop.Name) = $($prop.Value)"
            }
        }
    }

    if ($segEntries.Count -gt 0) {
        $bindingMaps[$segId] = $segEntries.ToArray()
    } else {
        Write-Verbose "      [binding] '$($seg.display_name)' -> no custom profile bindings"
    }
}
Write-Progress -Activity 'Reading profile binding maps' -Completed
Write-Host "      Segments with profile bindings: $($bindingMaps.Count) of $segTotal"

$export = [ordered]@{
    export_version       = '2.1'
    export_timestamp     = (Get-Date -Format 'o')
    source_manager       = $NSXManager
    source_version       = $ver.product_version
    segment_filter       = $SegmentFilter
    segments             = $segments
    segment_profiles     = @($customProfiles.Values)
    segment_binding_maps = $bindingMaps
    # id -> name of the source transport zones, for the Import picker (#10)
    transport_zone_names = $script:TzNames
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
$jsonFull = (Resolve-Path -LiteralPath $jsonPath).Path
$csvFull  = (Resolve-Path -LiteralPath $csvPath).Path
Write-Box -Title 'EXPORT COMPLETE' -Color Green -Rows ([ordered]@{
    'Exported from'     = $NSXManager
    'Segments exported' = $segments.Count
    'Profiles exported' = $customProfiles.Count
    'Tier-1 gateways'   = $t1Ids.Count
    'JSON'              = $jsonFull
    'CSV (edit me!)'    = $csvFull
})
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Green
Write-Host '  1. Fill in the NewName column of the CSV (leave NewName = OldName to keep a name):' -ForegroundColor Green
Write-Host "     $csvFull" -ForegroundColor Gray
Write-Host '  2. Dry run, then the import. Without -InputPath and -NSXManager it asks for both:' -ForegroundColor Green
Write-Host "     .\Import-NSXSegments.ps1 -InputPath '$jsonFull' -WhatIf" -ForegroundColor Gray
Write-Host ''

# Offer to open the CSV (Windows, someone at the keyboard)
$onWindows = if (Test-Path Variable:IsWindows) { $IsWindows } else { $true }
if ($onWindows -and (Test-InteractiveInput)) {
    $open = Read-Answer '  Open the CSV now? (y/N)'
    if ($open -match '^(y|yes|j|ja)$') { Invoke-Item -LiteralPath $csvFull }
}

# Exit codes (#10): 0 export written or nothing to export, 1 fatal error (thrown)
exit 0
