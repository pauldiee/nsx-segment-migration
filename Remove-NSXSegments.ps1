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
    as an encrypted XML file in your profile directory (Windows DPAPI). On
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
    Version : 1.5
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Toolkit : Export-NSXSegments.ps1 / Import-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
    GitHub  : https://github.com/pauldiee/nsx-segment-migration

    Exit codes: 0 done, nothing selected, aborted or dry run; 1 fatal error;
    2 finished with errors.

    Changelog
    ---------
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
    # Central credential resolution used by all three scripts.
    # Resolution order:
    #   1. -Credential parameter supplied on the command line -> use as-is
    #   2. Saved credential file found for this NSX Manager  -> offer to use or reset
    #   3. No credential available                           -> prompt, then offer to save
    param([System.Management.Automation.PSCredential]$Supplied, [string]$Manager)

    # Command-line credential takes priority - no interaction needed
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
                '1' {
                    Write-Host "  Using saved credential." -ForegroundColor Green
                    Write-Host ""
                    return $saved
                }
                '2' {
                    $cred = Read-NSXCredential
                    Save-Credential -Cred $cred -Manager $Manager
                    return $cred
                }
                '3' {
                    return Read-NSXCredential
                }
                default { Write-Host "  Enter 1, 2 or 3" -ForegroundColor Red }
            }
        }
    }

    # No saved credential - prompt and offer to save
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
    # Read-Host is used instead of Get-Credential because Get-Credential
    # can return null in some PowerShell hosts and execution contexts.
    $user = Read-Answer "  NSX username"
    $pass = Read-Host "  NSX password" -AsSecureString
    if ($null -eq $pass) { throw "No console input for the NSX password. Run the script interactively or pass -Credential." }
    return [System.Management.Automation.PSCredential]::new($user, $pass)
}

# =============================================================================
#  SCRIPT METADATA
# =============================================================================

$ScriptMeta = @{
    Name    = "Remove-NSXSegments.ps1"
    Version = "1.5"
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

    if (-not $PSCmdlet.ShouldProcess($NSXManager, "DELETE segment '$segName' (and its profile binding maps)")) { continue }

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

# Exit codes (#10): 0 done, 1 fatal error (thrown), 2 finished with errors
if ($totalErrors -gt 0) { exit 2 }
exit 0
