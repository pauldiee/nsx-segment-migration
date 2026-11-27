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
    as an encrypted XML file in your profile directory (Windows DPAPI). On
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
    FQDN or IP address of the source NSX Manager.

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
    Version : 2.4
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Pair    : Import-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
    GitHub  : https://github.com/pauldiee/nsx-segment-migration

    Exit codes: 0 export written or nothing to export, 1 fatal error.

    Changelog
    ---------
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
    [Parameter(Mandatory)]
    [string]$NSXManager,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputBase = ("./nsx-export_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')),

    [string]$SegmentFilter = '*',

    [switch]$NoSearch,

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
        $msg = Get-NSXErrorText -ErrorRecord $_
        Write-Verbose "  API error [$Method $Path] -> HTTP $code : $msg"
        throw "HTTP ${code}: $msg"
    }
}

function Get-NSXErrorText {
    # Returns NSX's own error_message (plus related errors) from a failed call,
    # or the exception text when the body is not NSX JSON (#10).
    param($ErrorRecord)
    $raw = if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $ErrorRecord.ErrorDetails.Message } else { '' }
    if ($raw) {
        try {
            $j = $raw | ConvertFrom-Json
            if ($j.PSObject.Properties['error_message']) {
                $text = "$($j.error_message)"
                if ($j.PSObject.Properties['related_errors'] -and $j.related_errors) {
                    $text += ' ' + ((@($j.related_errors) | ForEach-Object { $_.error_message }) -join ' ')
                }
                return $text.Trim()
            }
        } catch { }
        return $raw.Trim()
    }
    return $ErrorRecord.Exception.Message
}

function Get-AllPages {
    # Follows NSX cursor-based pagination and returns all results as a flat array.
    # NSX returns a 'cursor' field in the response when more pages are available.
    # A List instead of += keeps large result sets linear (#10).
    param([string]$Path)
    $results = [System.Collections.Generic.List[object]]::new()
    $cursor  = $null
    do {
        $sep  = if ($Path -match '\?') { '&' } else { '?' }
        $page = if ($cursor) {
            Invoke-NSXApi -Path "$Path${sep}cursor=$cursor"
        } else {
            Invoke-NSXApi -Path $Path
        }
        if ($page -and $page.PSObject.Properties['results'] -and $page.results) {
            foreach ($r in $page.results) { $results.Add($r) }
        }
        $cursor = if ($page -and $page.PSObject.Properties['cursor']) { $page.cursor } else { $null }
    } while ($cursor)
    return $results.ToArray()
}

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

# -----------------------------------------------------------------------------
#  Picker (#10): same behaviour as VIFolderManager and VITagManager. Numbers,
#  ranges, 'all' (or *), a filter on the whole line (wildcard or /text),
#  'reset', 'list', 'cancel'. Above $PickerListMax items the list is shortened.
# -----------------------------------------------------------------------------
$PickerListMax = 50
$script:PickerCancelled = $false
$script:TzNames = @{}

function Get-TransportZoneNames {
    # id -> display_name of the transport zones on this NSX, for the picker
    # (on NSX 9 the id is a UUID). Empty when the call fails.
    $names = @{}
    try {
        foreach ($tz in (Get-AllPages -Path '/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones')) {
            $names[$tz.id] = if ($tz.PSObject.Properties['display_name']) { $tz.display_name } else { $tz.id }
        }
    } catch { Write-Verbose "Transport zone names not read: $_" }
    return $names
}

function Test-CancelInput {
    param([string]$Text)
    return @('cancel', 'exit', 'quit', 'q') -contains $Text.ToLower()
}

function Write-PickerList {
    param([array]$Lines, [switch]$Full)
    $width = "$($Lines.Count)".Length
    $fmt   = '  [{0,' + $width + '}] {1}'
    if ($Full -or $Lines.Count -le $PickerListMax) {
        for ($i = 0; $i -lt $Lines.Count; $i++) { Write-Host ($fmt -f ($i + 1), $Lines[$i]) }
        return
    }
    for ($i = 0; $i -lt 5; $i++) { Write-Host ($fmt -f ($i + 1), $Lines[$i]) }
    Write-Host ('  ' + (' ' * ($width + 2)) + " ... $($Lines.Count - 10) more ...") -ForegroundColor DarkGray
    for ($i = $Lines.Count - 5; $i -lt $Lines.Count; $i++) { Write-Host ($fmt -f ($i + 1), $Lines[$i]) }
    Write-Host "`n  $($Lines.Count) items: too many to list. Narrow the list with a filter, or type 'list' to show them all." -ForegroundColor Yellow
}

function Get-SegmentLine {
    # One picker line per segment: name plus type, gateway and transport zone,
    # so a filter like /VLAN, /T1:<name> or /TZ:<name> picks a group at once
    param($Seg)
    $tags = [System.Collections.Generic.List[string]]::new()
    $isVlan = $Seg.PSObject.Properties['vlan_ids'] -and $Seg.vlan_ids
    if ($isVlan) { $tags.Add("VLAN $($Seg.vlan_ids -join ',')") } else { $tags.Add('overlay') }
    $conn = if ($Seg.PSObject.Properties['connectivity_path'] -and $Seg.connectivity_path) { "$($Seg.connectivity_path)" } else { '' }
    if ($conn -match '/tier-1s/([^/]+)') { $tags.Add("T1:$($Matches[1])") }
    elseif ($conn -match '/tier-0s/([^/]+)') { $tags.Add("T0:$($Matches[1])") }
    elseif (-not $isVlan) { $tags.Add('no gateway') }
    if ($Seg.PSObject.Properties['transport_zone_path'] -and $Seg.transport_zone_path) {
        $tzId = Split-Path $Seg.transport_zone_path -Leaf
        $tzName = if ($script:TzNames -and $script:TzNames.ContainsKey($tzId)) { $script:TzNames[$tzId] } else { $tzId }
        $tags.Add("TZ:$tzName")
    }
    return "$($Seg.display_name)  [$($tags -join '  ')]"
}

function Select-FromList {
    # Returns the selected items, sorted by display_name. Returns nothing when
    # the list is skipped (-AllowSkip and Enter without a filter) or cancelled;
    # a cancel also sets $script:PickerCancelled.
    param(
        [array]$Items,
        [string]$Title,
        [scriptblock]$LineText,
        [switch]$AllowSkip
    )
    $sorted = @($Items | Sort-Object display_name)
    $all    = @(foreach ($it in $sorted) { [pscustomobject]@{ Item = $it; Line = [string](& $LineText $it) } })
    $view   = $all
    $filter = ''

    Write-Host ''
    Write-Host "  $Title ($($all.Count))" -ForegroundColor Yellow
    Write-Host ''
    Write-PickerList -Lines @($view | ForEach-Object { $_.Line })
    Write-Host "`n  Numbers (1,3,5), a range (2-6) or a mix (1,3-5,8); 'all' (or *) takes every item shown;" -ForegroundColor Gray
    Write-Host "  'cancel' (or exit, quit, q) stops. Filter: a wildcard (*prod*) or /text for a substring, on the" -ForegroundColor Gray
    Write-Host "  whole line (so also /VLAN, /T1:<name>, /TZ:<name>); 'reset' clears it, 'list' shows every item." -ForegroundColor Gray
    if ($AllowSkip) { Write-Host "  Enter without a filter skips this list." -ForegroundColor Gray }
    Write-Host ''

    while ($true) {
        $prompt = if ($filter) { "  Select (filter: $filter, $($view.Count) shown)" } else { '  Select' }
        $raw    = Read-Answer $prompt
        if (Test-CancelInput $raw) {
            Write-Host '  Cancelled.' -ForegroundColor Yellow
            $script:PickerCancelled = $true
            return
        }
        if ($raw -eq 'list') { Write-PickerList -Lines @($view | ForEach-Object { $_.Line }) -Full; continue }
        if ($raw -eq 'reset' -or ($raw -eq '' -and $filter)) {
            $view = $all; $filter = ''
            Write-Host "`n  Filter cleared: $($view.Count) item(s)." -ForegroundColor Cyan
            Write-PickerList -Lines @($view | ForEach-Object { $_.Line })
            continue
        }
        if ($raw -eq '') {
            if ($AllowSkip) { Write-Host '  Skipped.' -ForegroundColor Gray; return }
            continue
        }

        $chosen = $null
        if ($raw -eq 'all' -or $raw -eq '*') {
            $chosen = $view
        } elseif ($raw -match '[*?]' -or $raw.StartsWith('/')) {
            $pattern = if ($raw.StartsWith('/')) { '*' + [WildcardPattern]::Escape($raw.Substring(1)) + '*' } else { $raw }
            $hits    = @($all | Where-Object { $_.Line -like $pattern })
            if ($hits.Count -eq 0) {
                Write-Host "  Nothing matches '$raw'; the list is unchanged." -ForegroundColor Yellow
                continue
            }
            $view = $hits; $filter = $raw
            Write-Host "`n  Filter '$filter': $($view.Count) of $($all.Count) item(s), renumbered." -ForegroundColor Cyan
            Write-PickerList -Lines @($view | ForEach-Object { $_.Line })
            continue
        } else {
            $indices = [System.Collections.Generic.HashSet[int]]::new()
            $ok      = $true
            foreach ($token in ($raw -split ',')) {
                $token = $token.Trim()
                if ($token -match '^(\d+)-(\d+)$') {
                    $from = [int]$Matches[1]; $to = [int]$Matches[2]
                    if ($from -lt 1 -or $to -gt $view.Count -or $from -gt $to) {
                        Write-Host "  Invalid range '$token': valid is 1-$($view.Count)." -ForegroundColor Red
                        $ok = $false; break
                    }
                    foreach ($n in $from..$to) { [void]$indices.Add($n) }
                } elseif ($token -match '^\d+$') {
                    $n = [int]$token
                    if ($n -lt 1 -or $n -gt $view.Count) {
                        Write-Host "  Invalid number '$token': valid is 1-$($view.Count)." -ForegroundColor Red
                        $ok = $false; break
                    }
                    [void]$indices.Add($n)
                } else {
                    Write-Host "  Unrecognised input '$token'. Use numbers, ranges like 2-5, 'all', or a filter (*text* or /text)." -ForegroundColor Red
                    $ok = $false; break
                }
            }
            if (-not $ok) { continue }
            $chosen = @($indices | Sort-Object | ForEach-Object { $view[$_ - 1] })
        }

        $items = @($chosen | ForEach-Object { $_.Item })
        Write-Host "`n  Selected $($items.Count) of $($all.Count):" -ForegroundColor Green
        if ($items.Count -le 20) {
            $chosen | ForEach-Object { Write-Host "    - $($_.Line)" }
        } else {
            $chosen[0..9] | ForEach-Object { Write-Host "    - $($_.Line)" }
            Write-Host "    ... and $($items.Count - 10) more" -ForegroundColor DarkGray
        }
        Write-Host ''
        return $items
    }
}

function Select-Segments {
    # Segment picker (#10): see Select-FromList
    param([array]$Segments)
    return Select-FromList -Items $Segments -Title 'SELECT SEGMENTS TO EXPORT' -LineText { param($s) Get-SegmentLine -Seg $s }
}

function Read-Answer {
    # Read-Host returns $null when there is no console input (redirected or
    # closed stdin, a scheduled task). Stop with a clear message instead of
    # failing on .Trim() of $null (#3).
    param([string]$Prompt)
    $answer = Read-Host $Prompt
    if ($null -eq $answer) {
        throw "No console input for the prompt '$($Prompt.Trim())'. Run the script in an interactive PowerShell window (pass -Credential to skip the credential prompts)."
    }
    return $answer.Trim()
}

function Get-CredentialPath {
    # creds\<manager>.cred next to the script, like the other tools (#3).
    param([string]$Manager)
    $safe = $Manager -replace '[^a-zA-Z0-9.\-]', '_'
    return Join-Path (Join-Path $PSScriptRoot 'creds') "$safe.cred"
}

function Get-LegacyCredentialPath {
    # Where versions before #3 saved the credential: the user profile.
    param([string]$Manager)
    $home_ = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
    return Join-Path $home_ ".nsx_cred_$($Manager -replace '[^a-zA-Z0-9]','_').xml"
}

function Get-SavedCredential {
    # Loads a saved credential for the given NSX Manager: creds\<manager>.cred
    # next to the script, or the old file in the user profile if only that
    # one exists. Returns the PSCredential, or $null if there is none.
    param([string]$Manager)
    foreach ($path in (Get-CredentialPath -Manager $Manager), (Get-LegacyCredentialPath -Manager $Manager)) {
        if (Test-Path $path) {
            try {
                $cred = Import-Clixml -Path $path
                if ($path -eq (Get-LegacyCredentialPath -Manager $Manager)) {
                    Write-Host "      Using the old credential file $path; choose [2] to save it in creds\ next to the script." -ForegroundColor Gray
                }
                return $cred
            } catch { }
        }
    }
    return $null
}

function Save-Credential {
    # Saves a credential to creds\<manager>.cred next to the script. On
    # Windows Export-Clixml encrypts the password with DPAPI (only this user
    # on this machine can read it); on Linux and macOS it is NOT encrypted.
    param([System.Management.Automation.PSCredential]$Cred, [string]$Manager)
    $path = Get-CredentialPath -Manager $Manager
    $dir  = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Cred | Export-Clixml -Path $path
    Write-Host "      Credential saved to: $path" -ForegroundColor Gray
    $onWindows = if (Test-Path Variable:IsWindows) { $IsWindows } else { $true }
    if (-not $onWindows) {
        Write-Host "      Note: on this OS the password in that file is not encrypted." -ForegroundColor Yellow
    }
}

function Remove-SavedCredential {
    # Deletes the saved credential file(s) for the given NSX Manager.
    param([string]$Manager)
    foreach ($path in (Get-CredentialPath -Manager $Manager), (Get-LegacyCredentialPath -Manager $Manager)) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Force
            Write-Host "      Saved credential removed: $path" -ForegroundColor Gray
        }
    }
}

function Resolve-Credential {
    # Central credential resolution. Resolution order:
    #   1. -Credential supplied on the command line  -> use as-is, no prompts
    #   2. Saved credential file found for this NSX Manager -> offer to use or reset
    #   3. No credential available -> prompt for username/password, offer to save
    param([System.Management.Automation.PSCredential]$Supplied, [string]$Manager)

    if ($Supplied) { return $Supplied }

    $saved = Get-SavedCredential -Manager $Manager

    if ($saved) {
        Write-Host ""
        Write-Host "  Saved credential found for '$Manager' (user: $($saved.UserName))" -ForegroundColor Cyan
        Write-Host "  [1] Use saved credential"
        Write-Host "  [2] Enter new credential and save over existing"
        Write-Host "  [3] Enter new credential without saving"
        Write-Host ""

        while ($true) {
            $choice = Read-Answer "  Select"
            switch ($choice) {
                '1' { Write-Host "  Using saved credential." -ForegroundColor Green
                      Write-Host ""; return $saved }
                '2' { $cred = Read-NSXCredential
                      Save-Credential -Cred $cred -Manager $Manager
                      return $cred }
                '3' { return Read-NSXCredential }
                default { Write-Host "  Enter 1, 2 or 3" -ForegroundColor Red }
            }
        }
    }

    # No saved credential - prompt then offer to save
    $cred = Read-NSXCredential
    Write-Host ""
    $save = Read-Answer "  Save credential for future runs? (Y/N)"
    if ($save -eq 'Y' -or $save -eq 'y') {
        Save-Credential -Cred $cred -Manager $Manager
    }
    Write-Host ""
    return $cred
}

function Read-NSXCredential {
    # Prompts for username and password using Read-Host.
    # Read-Host is used instead of Get-Credential because Get-Credential can
    # return null in some PowerShell hosts under Set-StrictMode, which causes
    # a PropertyNotFoundException on the first property access.
    $user = Read-Answer "  NSX username"
    $pass = Read-Host "  NSX password" -AsSecureString
    if ($null -eq $pass) { throw "No console input for the NSX password. Run the script interactively or pass -Credential." }
    return [System.Management.Automation.PSCredential]::new($user, $pass)
}

# =============================================================================
#  SCRIPT METADATA
# =============================================================================

$ScriptMeta = @{
    Name    = "Export-NSXSegments.ps1"
    Version = "2.4"
    Author  = "Paul van Dieen"
    Blog    = "https://www.hollebollevsan.nl"
    Date    = "2026-11-26"
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
Write-Host ("=" * $bannerWidth) -ForegroundColor DarkCyan
Write-Host ""

$jsonPath = "$OutputBase.json"
$csvPath  = "$OutputBase.csv"

$Credential = Resolve-Credential -Supplied $Credential -Manager $NSXManager
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

# Exit codes (#10): 0 export written or nothing to export, 1 fatal error (thrown)
exit 0
