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
    PSCredential for the NSX Manager admin account. Prompted if omitted.

.PARAMETER SegmentFilter
    Wildcard applied to segment display_name before the selection menu appears.
    Default: '*' (show all segments).

.PARAMETER SkipCertCheck
    Bypass TLS certificate validation. Use for self-signed certificates.

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

.EXAMPLE
    # Use a saved credential so you are not prompted each run
    $cred = Import-Clixml "$env:USERPROFILE\nsx-cred.xml"
    .\Remove-NSXSegments.ps1 -NSXManager nsx.corp.local -Credential $cred -SkipCertCheck

.NOTES
    Version : 1.1
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Toolkit : Export-NSXSegments.ps1 / Import-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$NSXManager,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$SegmentFilter = '*',

    [switch]$SkipCertCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

function Get-BasicAuthHeader {
    # Builds the Authorization and Content-Type headers for every API call.
    param([System.Management.Automation.PSCredential]$Cred)
    $pair    = "$($Cred.UserName):$($Cred.GetNetworkCredential().Password)"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    return @{ Authorization = "Basic $encoded"; 'Content-Type' = 'application/json' }
}

function Set-TlsSkipCert {
    # Disables TLS certificate validation for environments with self-signed certs.
    # Uses a compiled .NET delegate because assigning a PowerShell scriptblock to
    # ServicePointManager.ServerCertificateValidationCallback is silently ignored
    # under PS5 / .NET 4.x. The compiled approach works on both PS5 and PS7.
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
    # Issues a single REST call to the NSX Manager and returns the parsed JSON
    # response. Throws on any non-2xx HTTP status so callers can use try/catch.
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
    # Follows NSX cursor-based pagination and returns all results as a flat array.
    # NSX returns a 'cursor' field in the response when more pages are available.
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

function Select-Objects {
    # Generic numbered selection menu used for both segments and profiles.
    # $Items       : array of objects with at least a 'display_name' property.
    # $ExtraInfo   : optional scriptblock(item) -> string shown in brackets after
    #                the name (e.g. VLAN id, profile type). Return empty to omit.
    # Returns the selected subset as an array, or an empty array if skipped.
    param(
        [string]$Title,
        [string]$Subtitle = 'Numbers, ranges (1-5), * for all, Enter to skip.',
        [array]$Items,
        [scriptblock]$ExtraInfo = $null
    )

    $sorted = @($Items | Sort-Object display_name)
    $total  = $sorted.Count

    Write-Host ""
    Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ("|  {0,-48}|" -f $Title)                              -ForegroundColor Yellow
    Write-Host ("|  {0,-48}|" -f $Subtitle)                           -ForegroundColor Yellow
    Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""

    for ($i = 0; $i -lt $total; $i++) {
        $item = $sorted[$i]
        $num  = ($i + 1).ToString().PadLeft($total.ToString().Length)
        $hint = if ($ExtraInfo) {
            $info = & $ExtraInfo $item
            if ($info) { "  [$info]" } else { '' }
        } else { '' }
        Write-Host ("  [{0}] {1}{2}" -f $num, $item.display_name, $hint)
    }

    Write-Host ""

    while ($true) {
        $raw = (Read-Host "  Select (or Enter to skip)").Trim()

        # Empty input means skip this category entirely
        if (-not $raw) {
            Write-Host "  Skipped" -ForegroundColor Gray
            Write-Host ""
            return @()
        }

        if ($raw -eq '*') {
            Write-Host ""
            Write-Host "  Selected all $total item(s)" -ForegroundColor Green
            Write-Host ""
            return $sorted
        }

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
            Write-Host ""
            Write-Host "  Selected $($selected.Count) of $total item(s):" -ForegroundColor Green
            $selected | ForEach-Object { Write-Host "    - $($_.display_name)" }
            Write-Host ""
            return $selected
        } elseif ($valid) {
            Write-Host "  Nothing selected - enter at least one number or press Enter to skip" -ForegroundColor Red
        }
    }
}

function Get-SegmentPortCount {
    # Returns the number of ports currently attached to a segment.
    # NSX will reject a segment DELETE if any ports remain. Checking this before
    # the confirmation prompt lets the operator see the problem before typing YES.
    param([string]$SegmentId)
    try {
        $ports = @(Get-AllPages -Path "/policy/api/v1/infra/segments/$SegmentId/ports")
        return $ports.Count
    } catch {
        # If the ports endpoint is unavailable assume zero to avoid false blocks
        return 0
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
#  MAIN
# =============================================================================

Write-Host @"
+==================================================+
|   Remove-NSXSegments.ps1  v1.1                   |
|   Compatible with NSX 4.x and 9.x                |
+==================================================+
"@ -ForegroundColor Cyan

# -- 1. Connect ---------------------------------------------------------------
if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter credentials for NSX Manager ($NSXManager)"
}
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
    $segmentsToDelete = @(Select-Objects `
        -Title    'SELECT SEGMENTS TO DELETE' `
        -Items    $filtered `
        -ExtraInfo {
            param($seg)
            $vlan = if ($seg.PSObject.Properties['vlan_ids'] -and $seg.vlan_ids) {
                        "VLAN $($seg.vlan_ids -join ',')"
                    } else { 'overlay' }
            $t1   = if ($seg.PSObject.Properties['connectivity_path'] -and
                        $seg.connectivity_path -and
                        $seg.connectivity_path -match '/tier-1s/([^/]+)') {
                        "T1:$($Matches[1])"
                    } else { '' }
            (@($vlan, $t1) | Where-Object { $_ }) -join '  '
        }
    )
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
    $portsWarnings = @()
    foreach ($seg in $segmentsToDelete) {
        $portCount = Get-SegmentPortCount -SegmentId $seg.id
        if ($portCount -gt 0) {
            $portsWarnings += "    '$($seg.display_name)' has $portCount port(s) still attached"
        }
    }
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
$confirm = (Read-Host "  Confirm").Trim()
if ($confirm -cne 'YES') {
    Write-Host "`n  Aborted. Nothing deleted." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

$okSegments  = 0
$errSegments = 0
$okProfiles  = 0
$errProfiles = 0
$errList     = @()

# Delete segments first.
# Each segment needs its profile binding maps removed before NSX will accept
# the segment DELETE. Binding map removal is silent housekeeping - no separate
# confirmation is needed as the operator already typed YES for the segment.
# After all segments are gone the profiles can be safely deleted.
foreach ($seg in $segmentsToDelete) {
    $segId   = $seg.id
    $segName = $seg.display_name

    # Remove all profile binding maps attached to this segment
    $bindingMaps = @(Get-BindingMapsForSegment -SegmentId $segId)
    foreach ($bm in $bindingMaps) {
        $bmPath = "/policy/api/v1/infra/segments/$segId/$($bm.bmtype)/$($bm.bmid)"
        try {
            $null = Invoke-NSXApi -Path $bmPath -Method DELETE
            Write-Host "      Removed binding map $($bm.bmtype)/$($bm.bmid)" -ForegroundColor Gray
        } catch {
            # Non-fatal - log and continue. If the binding map is already gone
            # or the DELETE fails for another reason the segment DELETE may still
            # succeed; NSX will report the real error if it does not.
            Write-Warning "      Could not remove binding map $($bm.bmtype)/$($bm.bmid) on '$segName': $_"
        }
    }

    # Delete the segment
    $segPath = "/policy/api/v1/infra/segments/$segId"
    if ($PSCmdlet.ShouldProcess($NSXManager, "DELETE segment '$segName'")) {
        try {
            $null = Invoke-NSXApi -Path $segPath -Method DELETE
            Write-Host "  [OK] Segment '$segName'" -ForegroundColor Green
            $okSegments++
        } catch {
            Write-Warning "  [FAIL] Segment '$segName': $_"
            $errList += "Segment '$segName': $_"
            $errSegments++
        }
    }
}

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
        $errList += "Profile '$profName': API path unknown"
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
            $errList += "Profile '$profName': $_"
            $errProfiles++
        }
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

if ($errList.Count -gt 0) {
    Write-Host "`nErrors:" -ForegroundColor Red
    $errList | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} else {
    Write-Host "All selected objects deleted successfully.`n" -ForegroundColor Green
}
