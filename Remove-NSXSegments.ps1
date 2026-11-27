#Requires -Version 5.1

<#
.SYNOPSIS
    Interactively selects and deletes NSX segments and/or custom segment
    profiles from any NSX Manager (4.x or 9.x).

.DESCRIPTION
    Connects to the NSX Manager and presents separate selection menus for
    segments and segment profiles. After a confirmation prompt, the selected
    objects are permanently deleted via the Policy REST API.

    Deletion order
    --------------
    Segments are always deleted before profiles. This is required because:
      1. NSX rejects segment deletion while profile binding maps still exist
         on the segment, so binding maps are removed first automatically.
      2. NSX rejects profile deletion while any segment still references it,
         so segments must be gone before the profiles they used can be removed.

    Safety features
    ---------------
    - Segment and profile menus are independent. Press Enter at either menu
      to skip that category - useful when you only want to remove profiles.
    - A confirmation prompt lists every object queued for deletion and requires
      you to type YES (case-sensitive) before anything is touched.
    - Segments with ports still attached are flagged with a warning before the
      confirmation prompt. NSX will reject their deletion until all ports are
      removed.
    - -WhatIf previews the full deletion plan without executing any API calls.

    Credentials
    -----------
    On first run you are prompted for username and password, then asked whether
    to save them for future runs. Saved credentials are stored per NSX Manager
    in creds\<manager>.cred next to the scripts (encrypted with DPAPI on
    Windows, not encrypted on Linux and macOS). On
    subsequent runs a menu offers to reuse, overwrite, or ignore the saved
    credential. Pass -Credential to bypass the interactive flow entirely.

    NSX version compatibility
    -------------------------
    NSX 4.x stores profiles under  /infra/segment-profiles/<type>/
    NSX 9.x stores profiles under  /infra/<type>/
    Both formats are tried automatically; whichever responds is used for the
    subsequent DELETE call on the same object.

    Profile binding map types
    -------------------------
    segment-discovery-profile-binding-maps  (IP Discovery, MAC Discovery)
    segment-security-profile-binding-maps   (Segment Security, SpoofGuard)
    segment-qos-profile-binding-maps        (QoS)

.PARAMETER NSXManager
    FQDN or IP address of the NSX Manager.

.PARAMETER Credential
    PSCredential for the NSX Manager admin account.
    If omitted, the built-in credential manager handles prompting and saving.

.PARAMETER SegmentFilter
    Wildcard applied to segment display_name before the selection menu appears.
    Default: '*' (show all segments).

.PARAMETER NoSearch
    Check ports and read binding maps per segment instead of with the NSX
    search API. The script also falls back to this by itself when a search
    call fails.

.PARAMETER SkipCertCheck
    Bypass TLS certificate validation. Use for self-signed certificates.
    For internal CA certificates, import the CA root into the Windows Trusted
    Root store instead: Import-Certificate -FilePath ca.cer
    -CertStoreLocation Cert:\LocalMachine\Root

.EXAMPLE
    # Interactive delete - choose segments and/or profiles to remove
    .\Remove-NSXSegments.ps1 -NSXManager nsx.corp.local -SkipCertCheck

.EXAMPLE
    # Pre-filter the segment list before the menu appears
    .\Remove-NSXSegments.ps1 -NSXManager nsx.corp.local `
        -SegmentFilter "test-*" -SkipCertCheck

.EXAMPLE
    # Dry run - preview what would be deleted without touching NSX
    .\Remove-NSXSegments.ps1 -NSXManager nsx.corp.local -SkipCertCheck -WhatIf

.NOTES
    Version : 1.7
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Toolkit : Export-NSXSegments.ps1 / Import-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
    GitHub  : https://github.com/pauldiee/nsx-segment-migration

    Exit codes: 0 done, nothing selected, aborted or dry run; 1 fatal error;
    2 finished with errors.

    Changelog
    ---------
    1.7 - Closing line from the counts (#13): "n of m selected object(s)
          deleted; k declined at -Confirm and kept" instead of "All selected
          objects deleted successfully" when something was declined. A
          declined segment or profile is reported as [DECLINED] and counted
          in the summary.
    1.6 - Shared helpers moved to NSXSM-Common.ps1 (#11), unchanged: REST
          calls, pickers, prompts and credentials. The script stops with a
          clear message when NSXSM-Common.ps1 is missing or older than 1.0;
          the banner shows its version. Commands and parameters are the same.
          Help: credentials are in creds\ next to the scripts (since #3),
          not in the user profile.
    1.5 - Scale (#10): attached ports and profile binding maps via the NSX
          search API (one and three calls instead of one and three per
          segment), with -NoSearch and an automatic fallback; when a segment
          DELETE fails after a search read, its binding maps are read
          directly and the DELETE is retried once. Under -Confirm, No for a
          segment also keeps its binding maps (they were removed before the
          question). Port count unknown is reported instead of read as 0.
          Errors show NSX's error_message; exit code 2 when something
          failed. Running count [n/total]. Pickers as in VIFolderManager/
          VITagManager: filter on the whole line (wildcard or /text: /VLAN,
          /T1:<name>, /TZ:<name>), 'reset', 'list', 'all', 'cancel' (stops
          the run, nothing deleted); long lists are shortened.
    1.4 - Get-Help shows the full help again: blank line between
          #Requires and the help block (without it Get-Help ignored
          the whole help block).
    1.3 - Prompts without console input stop with a clear message instead
          of failing on .Trim() of $null. Credentials are saved in
          creds\<manager>.cred next to the script; the old file in the user
          profile is still read (#3).
    1.2 - Added built-in credential save/reset via Resolve-Credential.
          Replaced Get-Credential with Read-Host to fix null credential errors
          in non-interactive PowerShell hosts under Set-StrictMode.
          Added $ScriptMeta branding banner (Name, Author, Blog, Date).
    1.1 - Added port count check before confirmation prompt.
          Fixed extra confirmation prompts by removing ConfirmImpact = High.
          Binding map deletion no longer triggers ShouldProcess prompts.
    1.0 - Initial release. Interactive segment and profile selection menus.
          Automatic binding map removal before segment deletion.
          Typed YES confirmation gate. WhatIf support.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$NSXManager,

    [System.Management.Automation.PSCredential]$Credential,

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
if (-not (Test-Path Variable:NSXSMCommonVersion) -or [version]$NSXSMCommonVersion -lt [version]'1.0') {
    Write-Host "NSXSM-Common.ps1 next to this script is older than 1.0. Copy the whole folder of this release." -ForegroundColor Red
    exit 1
}

# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

function Get-ChildrenBySearch {
    # One paged search call for every object of the given resource types,
    # grouped by parent_path (the segment's path). Replaces one or three GETs
    # per segment (#10). Returns a hashtable parent_path -> list of
    # [pscustomobject]@{ bmtype; bmid } for binding maps, or of the raw
    # objects for other types. Throws when the search API is unavailable.
    param([hashtable]$TypeMap)
    $byParent = @{}
    foreach ($rt in $TypeMap.Keys) {
        foreach ($o in (Get-AllPages -Path "/policy/api/v1/search/query?query=resource_type:$rt")) {
            if (-not $o.PSObject.Properties['parent_path']) { continue }
            if (-not $byParent.ContainsKey($o.parent_path)) {
                $byParent[$o.parent_path] = [System.Collections.Generic.List[object]]::new()
            }
            $item = if ($TypeMap[$rt]) { [pscustomobject]@{ bmtype = $TypeMap[$rt]; bmid = $o.id } } else { $o }
            $byParent[$o.parent_path].Add($item)
        }
    }
    return $byParent
}

function Get-SegmentPath {
    param($Seg)
    if ($Seg.PSObject.Properties['path'] -and $Seg.path) { return $Seg.path }
    return "/infra/segments/$($Seg.id)"
}

function Select-Objects {
    # Profile picker (#10): see Select-FromList. $ExtraInfo returns the text
    # shown in brackets after the name (the profile type).
    param([string]$Title, [array]$Items, [scriptblock]$ExtraInfo = $null)
    $extra = $ExtraInfo
    $line  = {
        param($i)
        $info = if ($extra) { & $extra $i } else { '' }
        if ($info) { "$($i.display_name)  [$info]" } else { "$($i.display_name)" }
    }.GetNewClosure()
    return Select-FromList -Items $Items -Title $Title -LineText $line -AllowSkip
}
function Get-SegmentPortCount {
    # Returns the number of ports currently attached to a segment.
    # NSX will reject a segment DELETE if any ports remain. Checking this before
    # the confirmation prompt lets the operator see the problem before typing YES.
    # Returns -1 when the count could not be read (shown as "unknown", #10).
    param([string]$SegmentId)
    try {
        $ports = @(Get-AllPages -Path "/policy/api/v1/infra/segments/$SegmentId/ports")
        return $ports.Count
    } catch {
        return -1
    }
}

function Get-BindingMapsForSegment {
    # Returns all profile binding maps attached to a segment across all three
    # typed binding map endpoints. Each result carries the binding map type and
    # id, which together form the DELETE path used before the segment is removed.
    param([string]$SegmentId)

    $bindingMapTypes = @(
        'segment-discovery-profile-binding-maps',
        'segment-security-profile-binding-maps',
        'segment-qos-profile-binding-maps'
    )

    $found = @()
    foreach ($bmType in $bindingMapTypes) {
        try {
            $maps = @(Get-AllPages -Path "/policy/api/v1/infra/segments/$SegmentId/$bmType")
            foreach ($bm in $maps) {
                $found += [PSCustomObject]@{ bmtype = $bmType; bmid = $bm.id }
            }
        } catch {
            Write-Verbose "/$bmType not available for segment '$SegmentId'"
        }
    }
    return $found
}

# =============================================================================
#  SCRIPT METADATA
# =============================================================================

$ScriptMeta = @{
    Name    = "Remove-NSXSegments.ps1"
    Version = "1.7"
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

# -- 1. Connect ---------------------------------------------------------------
$Credential = Resolve-Credential -Supplied $Credential -Manager $NSXManager
if ($SkipCertCheck -and $PSVersionTable.PSVersion.Major -lt 6) { Set-TlsSkipCert }
$script:Headers = Get-BasicAuthHeader -Cred $Credential

Write-Host "`n[1/4] Verifying connectivity to $NSXManager ..." -ForegroundColor Cyan
$ver = Invoke-NSXApi -Path '/api/v1/node/version'
Write-Host "      NSX version : $($ver.product_version)" -ForegroundColor Green

# -- 2. Fetch and select segments ---------------------------------------------
Write-Host "`n[2/4] Fetching segments (filter: '$SegmentFilter') ..." -ForegroundColor Cyan
$allSegments = @(Get-AllPages -Path '/policy/api/v1/infra/segments')
$filtered    = @($allSegments | Where-Object { $_.display_name -like $SegmentFilter })
Write-Host "      Found $($filtered.Count) segment(s) matching filter out of $($allSegments.Count) total"

$segmentsToDelete = @()
if ($filtered.Count -gt 0) {
    $script:TzNames = Get-TransportZoneNames
    $segmentsToDelete = @(Select-FromList -Items $filtered -Title 'SELECT SEGMENTS TO DELETE' `
        -LineText { param($s) Get-SegmentLine -Seg $s } -AllowSkip)
    if ($script:PickerCancelled) { Write-Host "`n  Nothing deleted." -ForegroundColor Yellow; exit 0 }
} else {
    Write-Host "      No segments matched filter '$SegmentFilter' - skipping segment selection"
}

# -- 3. Fetch and select segment profiles ------------------------------------
# Profile API paths differ by NSX version:
#   NSX 4.x : /infra/segment-profiles/<type>/
#   NSX 9.x : /infra/<type>/
# Both are tried for each profile type. The path that responds is stored on
# each profile object as _apiBasePath so the correct DELETE path can be built
# later without guessing the NSX version again.
Write-Host "`n[3/4] Fetching custom segment profiles ..." -ForegroundColor Cyan

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

$customProfiles = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($ptype in $profileTypes.Keys) {
    $profiles    = $null
    $workingPath = $null
    foreach ($apiPath in $profileTypes[$ptype]) {
        try {
            $profiles    = Get-AllPages -Path $apiPath
            $workingPath = $apiPath
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

    # Exclude built-in default profiles; only surface custom ones to the operator
    foreach ($p in ($profiles | Where-Object {
            $_.PSObject.Properties['path'] -and
            $_.path -notmatch '/default-' -and
            $_.PSObject.Properties['display_name'] -and
            $_.display_name -notmatch '^default' })) {
        # Tag with type and working path so DELETE can use the same format as GET
        $p | Add-Member -MemberType NoteProperty -Name '_ptype'       -Value $ptype       -Force
        $p | Add-Member -MemberType NoteProperty -Name '_apiBasePath' -Value $workingPath -Force
        $customProfiles.Add($p)
    }
}

Write-Host "      Found $($customProfiles.Count) custom profile(s)"

$profilesToDelete = @()
if ($customProfiles.Count -gt 0) {
    $profilesToDelete = @(Select-Objects `
        -Title    'SELECT SEGMENT PROFILES TO DELETE' `
        -Items    $customProfiles `
        -ExtraInfo {
            param($p)
            if ($p.PSObject.Properties['_ptype']) { $p._ptype } else { '' }
        }
    )
    if ($script:PickerCancelled) { Write-Host "`n  Nothing deleted." -ForegroundColor Yellow; exit 0 }
} else {
    Write-Host "      No custom profiles found - skipping profile selection"
}

# Exit cleanly if neither category has anything selected
if ($segmentsToDelete.Count -eq 0 -and $profilesToDelete.Count -eq 0) {
    Write-Host "`nNothing selected. Exiting." -ForegroundColor Yellow
    exit 0
}

# -- 4. Confirm and delete ----------------------------------------------------
Write-Host "`n[4/4] Confirmation" -ForegroundColor Cyan
Write-Host ""

# Check for segments with ports still attached before the operator types YES.
# NSX will reject the DELETE for those segments, so warn upfront to avoid a
# partially completed run where some segments are deleted and others are not.
if ($segmentsToDelete.Count -gt 0) {
    Write-Host "      Checking for attached ports ..."
    $portsWarnings = [System.Collections.Generic.List[string]]::new()
    # One search call for all segment ports (#10); per segment as fallback
    $portsByParent = $null
    if (-not $NoSearch) {
        try { $portsByParent = Get-ChildrenBySearch -TypeMap @{ 'SegmentPort' = $null } }
        catch { Write-Warning "      Search API not available ($_); checking ports per segment" }
    }
    $segNo = 0
    foreach ($seg in $segmentsToDelete) {
        $segNo++
        $portCount = if ($null -ne $portsByParent) {
            $sp = Get-SegmentPath -Seg $seg
            if ($portsByParent.ContainsKey($sp)) { $portsByParent[$sp].Count } else { 0 }
        } else {
            Write-Progress -Activity 'Checking attached ports' -Status "$segNo of $($segmentsToDelete.Count)" -PercentComplete ([int](100 * $segNo / $segmentsToDelete.Count))
            Get-SegmentPortCount -SegmentId $seg.id
        }
        if ($portCount -gt 0) {
            $portsWarnings.Add("    '$($seg.display_name)' has $portCount port(s) still attached")
        } elseif ($portCount -lt 0) {
            $portsWarnings.Add("    '$($seg.display_name)': port count unknown (ports API did not answer)")
        }
    }
    Write-Progress -Activity 'Checking attached ports' -Completed
    if ($portsWarnings.Count -gt 0) {
        Write-Host ""
        Write-Host "  WARNING: the following segments have ports attached." -ForegroundColor Yellow
        Write-Host "  NSX will reject their deletion. Remove all ports first." -ForegroundColor Yellow
        $portsWarnings | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        Write-Host ""
    }
}

Write-Host "  The following objects will be permanently deleted:" -ForegroundColor Red
Write-Host ""

if ($segmentsToDelete.Count -gt 0) {
    Write-Host "  Segments ($($segmentsToDelete.Count)):" -ForegroundColor White
    foreach ($seg in $segmentsToDelete) {
        $vlan = if ($seg.PSObject.Properties['vlan_ids'] -and $seg.vlan_ids) {
                    " [VLAN $($seg.vlan_ids -join ',')]"
                } else { ' [overlay]' }
        Write-Host "    - $($seg.display_name)$vlan" -ForegroundColor Red
    }
    Write-Host ""
}

if ($profilesToDelete.Count -gt 0) {
    Write-Host "  Segment Profiles ($($profilesToDelete.Count)):" -ForegroundColor White
    foreach ($prof in $profilesToDelete) {
        $ptype = if ($prof.PSObject.Properties['_ptype']) { " [$($prof._ptype)]" } else { '' }
        Write-Host "    - $($prof.display_name)$ptype" -ForegroundColor Red
    }
    Write-Host ""
}

if ($WhatIfPreference) {
    Write-Host "  [WhatIf] No changes made." -ForegroundColor Cyan
    exit 0
}

Write-Host "  Type YES and press Enter to confirm, or anything else to abort:" -ForegroundColor Yellow
$confirm = Read-Answer "  Confirm"
if ($confirm -cne 'YES') {
    Write-Host "`n  Aborted. Nothing deleted." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

$okSegments  = 0
$errSegments = 0
$okProfiles  = 0
$errProfiles = 0
$declinedSegments = 0
$declinedProfiles = 0
$errList     = [System.Collections.Generic.List[string]]::new()

# Binding maps of all selected segments in three search calls (#10); per
# segment as fallback.
$bmTypeMap = @{
    'SegmentDiscoveryProfileBindingMap' = 'segment-discovery-profile-binding-maps'
    'SegmentSecurityProfileBindingMap'  = 'segment-security-profile-binding-maps'
    'SegmentQoSProfileBindingMap'       = 'segment-qos-profile-binding-maps'
}
$bmByParent = $null
if ($segmentsToDelete.Count -gt 0 -and -not $NoSearch) {
    try { $bmByParent = Get-ChildrenBySearch -TypeMap $bmTypeMap }
    catch { Write-Warning "      Search API not available ($_); reading binding maps per segment" }
}

function Remove-SegmentBindingMaps {
    # Deletes the given binding maps of one segment; failures are logged and
    # left to the segment DELETE, which reports the real error if it matters
    param([string]$SegId, [string]$SegName, [array]$Maps)
    foreach ($bm in $Maps) {
        $bmPath = "/policy/api/v1/infra/segments/$SegId/$($bm.bmtype)/$($bm.bmid)"
        try {
            $null = Invoke-NSXApi -Path $bmPath -Method DELETE
            Write-Verbose "      Removed binding map $($bm.bmtype)/$($bm.bmid)"
        } catch {
            Write-Warning "      Could not remove binding map $($bm.bmtype)/$($bm.bmid) on '$SegName': $_"
        }
    }
}

# Delete segments first.
# Each segment needs its profile binding maps removed before NSX will accept
# the segment DELETE. The binding maps go inside the segment's ShouldProcess,
# so answering No under -Confirm leaves the segment and its bindings alone
# (#10). After all segments are gone the profiles can be safely deleted.
$segNo    = 0
$segTotal = $segmentsToDelete.Count
foreach ($seg in $segmentsToDelete) {
    $segNo++
    $segId   = $seg.id
    $segName = $seg.display_name
    $counter = "[$segNo/$segTotal]"
    Write-Progress -Activity 'Deleting segments' -Status "$segNo of $segTotal" -PercentComplete ([int](100 * $segNo / $segTotal))

    # -WhatIf has stopped before this point, so No here is a No at -Confirm (#13)
    if (-not $PSCmdlet.ShouldProcess($NSXManager, "DELETE segment '$segName' (and its profile binding maps)")) {
        Write-Host "  $counter [DECLINED] Segment '$segName' - kept, with its binding maps" -ForegroundColor Yellow
        $declinedSegments++
        continue
    }

    # Remove all profile binding maps attached to this segment
    $bindingMaps = if ($null -ne $bmByParent) {
        $p = Get-SegmentPath -Seg $seg
        if ($bmByParent.ContainsKey($p)) { @($bmByParent[$p]) } else { @() }
    } else { @(Get-BindingMapsForSegment -SegmentId $segId) }
    Remove-SegmentBindingMaps -SegId $segId -SegName $segName -Maps $bindingMaps

    # Delete the segment. When the binding maps came from the search index and
    # the DELETE fails, read them per segment (the index can lag) and retry once.
    $segPath = "/policy/api/v1/infra/segments/$segId"
    try {
        $null = Invoke-NSXApi -Path $segPath -Method DELETE
        Write-Host "  $counter [OK] Segment '$segName'" -ForegroundColor Green
        $okSegments++
    } catch {
        $firstError = "$_"
        $retried = $false
        if ($null -ne $bmByParent) {
            $direct = @(Get-BindingMapsForSegment -SegmentId $segId)
            if ($direct.Count -gt 0) {
                Remove-SegmentBindingMaps -SegId $segId -SegName $segName -Maps $direct
                try {
                    $null = Invoke-NSXApi -Path $segPath -Method DELETE
                    Write-Host "  $counter [OK] Segment '$segName' (second try, after removing $($direct.Count) binding map(s))" -ForegroundColor Green
                    $okSegments++
                    $retried = $true
                } catch { $firstError = "$_" }
            }
        }
        if (-not $retried) {
            Write-Warning "  $counter [FAIL] Segment '$($segName)': $firstError"
            $errList.Add("Segment '$($segName)': $firstError")
            $errSegments++
        }
    }
}
Write-Progress -Activity 'Deleting segments' -Completed

# Delete profiles after all segments have been removed.
# Build the DELETE path from the API base path recorded during the GET so we
# use the same path format (NSX 4 legacy or NSX 9 flat) that is known to work.
foreach ($prof in $profilesToDelete) {
    $profId   = $prof.id
    $profName = $prof.display_name

    $profPath = if ($prof.PSObject.Properties['_apiBasePath'] -and $prof._apiBasePath) {
        "$($prof._apiBasePath)/$profId" -replace '^/policy/api/v1', ''
    } elseif ($prof.PSObject.Properties['path'] -and $prof.path) {
        $prof.path
    } else {
        $null
    }

    if (-not $profPath) {
        Write-Warning "  [FAIL] Profile '$profName': could not determine API path - skipping"
        $errList.Add("Profile '$profName': API path unknown")
        $errProfiles++
        continue
    }

    $apiPath = "/policy/api/v1$profPath"
    if ($PSCmdlet.ShouldProcess($NSXManager, "DELETE profile '$profName'")) {
        try {
            $null = Invoke-NSXApi -Path $apiPath -Method DELETE
            Write-Host "  [OK] Profile '$profName'" -ForegroundColor Green
            $okProfiles++
        } catch {
            Write-Warning "  [FAIL] Profile '$profName': $_"
            $errList.Add("Profile '$profName': $_")
            $errProfiles++
        }
    } else {
        Write-Host "  [DECLINED] Profile '$profName' - kept" -ForegroundColor Yellow
        $declinedProfiles++
    }
}

# -- Summary ------------------------------------------------------------------
$totalErrors = $errSegments + $errProfiles
$statusColor = if ($totalErrors -eq 0) { 'Green' } else { 'Yellow' }

Write-Host @"

+==================================================+
|   DELETE SUMMARY                                 |
+==================================================+
|  Segments  OK / Failed : $("$okSegments / $errSegments".PadRight(24))|
|  Profiles  OK / Failed : $("$okProfiles / $errProfiles".PadRight(24))|
+==================================================+
"@ -ForegroundColor $statusColor
$declined = $declinedSegments + $declinedProfiles
if ($declined -gt 0) {
    Write-Host "  Declined at -Confirm, kept: $declinedSegments segment(s), $declinedProfiles profile(s)" -ForegroundColor Yellow
}

if ($errList.Count -gt 0) {
    Write-Host "`nErrors:" -ForegroundColor Red
    $errList | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} elseif ($declined -eq 0) {
    Write-Host "All selected objects deleted successfully.`n" -ForegroundColor Green
} else {
    # Closing line from the counts (#13)
    $selected = $segmentsToDelete.Count + $profilesToDelete.Count
    $deleted  = $okSegments + $okProfiles
    $color    = if ($deleted -eq 0) { 'Yellow' } else { 'Green' }
    Write-Host "$deleted of $selected selected object(s) deleted; $declined declined at -Confirm and kept.`n" -ForegroundColor $color
}

# Exit codes (#10): 0 done, 1 fatal error (thrown), 2 finished with errors
if ($totalErrors -gt 0) { exit 2 }
exit 0
