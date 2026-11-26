#Requires -Version 5.1

<#
.SYNOPSIS
    Imports NSX segments, custom segment profiles, and profile binding maps
    into a target NSX Manager from the JSON + CSV pair produced by
    Export-NSXSegments.ps1.

.DESCRIPTION
    Reads the export JSON and the companion CSV name-mapping table, then
    PATCHes each object into the target NSX Manager via the Policy REST API.

    The CSV is auto-discovered by replacing the .json extension with .csv.
    Override with -MappingPath if the files are in different locations.

    CSV name-mapping rules
    ----------------------
    Rows where NewName = OldName (or NewName is blank) are treated as no-op.
    Segment rows        : renames the segment display_name and id.
    SegmentProfile rows : renames the profile; all binding paths auto-updated.
    T1Gateway rows      : remaps the connectivity_path T1 reference.

    Import order
    ------------
    1. Custom segment profiles  (must exist before segments reference them)
    2. Segments                 (only those selected in the menu)
    3. Profile binding maps     (applied per-segment after the segment is created)

    Profiles are always imported regardless of segment selection, so no
    segment ever references a missing profile.

    Objects that already exist on the target
    ----------------------------------------
    Before writing, the script lists the segments and profiles on the target.
    A PATCH merges into an existing object with the same id, so a selected
    segment or profile that is already there is skipped and listed (binding
    maps then point at the existing profile). Pass -UpdateExisting to PATCH
    them anyway, for example to re-apply an export after a partial run.

    Exit codes
    ----------
    0 success or dry run, 1 fatal error, 2 finished with errors (a profile,
    segment or binding map failed; see the Errors list).

    Credentials
    -----------
    On first run you are prompted for username and password, then asked whether
    to save them for future runs. Saved credentials are stored per NSX Manager
    as an encrypted XML file in your profile directory (Windows DPAPI). On
    subsequent runs a menu offers to reuse, overwrite, or ignore the saved
    credential. Pass -Credential to bypass the interactive flow entirely.

    Transport zone selection
    ------------------------
    After connecting, an interactive menu lists all available transport zones.
    The selected TZ is applied to all imported segments. Press Enter to keep
    the transport zone from the export unchanged. Supply -TransportZoneId to
    skip the menu entirely (useful for automation).

    Overlay segment validation
    --------------------------
    If the selected transport zone is an overlay zone (OVERLAY_BACKED,
    OVERLAY_STANDARD or OVERLAY_ENS), the script checks each
    segment for the two fields NSX requires:
      - connectivity_path  (T0 or T1 gateway connection)
      - subnets            (gateway IP and prefix, e.g. 192.168.10.1/24)
    Missing values trigger an interactive prompt before any import begins.
    Pressing Enter at either prompt skips that field. VLAN-backed segments
    skip this step entirely. With -Disconnected the check is skipped.

    Disconnected import (-Disconnected)
    -----------------------------------
    Imports every selected segment without a gateway connection: the
    connectivity_path is removed before the PATCH, subnets are kept. Use it
    for overlay subnets that keep their IP addresses in a side-by-side
    migration without HCX, where the old Tier-1 keeps the gateway until the
    cutover. NSX: "If a segment is not connected to a gateway, subnet is
    optional"; connectivity can be changed from None to a Tier-0 or Tier-1
    later. The summary lists each segment with the gateway to connect it to
    at the cutover (the source gateway, Tier-1 renamed per the CSV).

    NSX version compatibility
    -------------------------
    NSX 4.x stores profiles under  /infra/segment-profiles/<type>/
    NSX 9.x stores profiles under  /infra/<type>/
    Both formats are tried automatically. The path that succeeds is recorded
    and used for all subsequent binding map operations on that profile.

    Profile binding map types
    -------------------------
    segment-discovery-profile-binding-maps  (IP Discovery, MAC Discovery)
    segment-security-profile-binding-maps   (Segment Security, SpoofGuard)
    segment-qos-profile-binding-maps        (QoS)

.PARAMETER NSXManager
    FQDN or IP address of the target NSX Manager.

.PARAMETER Credential
    PSCredential for the NSX Manager admin account.
    If omitted, the built-in credential manager handles prompting and saving.

.PARAMETER InputPath
    Path to the .json file produced by Export-NSXSegments.ps1.
    The companion .csv is expected at the same path with a .csv extension
    unless -MappingPath is specified.

.PARAMETER MappingPath
    Optional explicit path to the CSV name-mapping file.

.PARAMETER TransportZoneId
    Transport zone id to apply to all imported segments. If omitted, an
    interactive menu lets you choose from the transport zones on the target NSX.
    Press Enter at the menu to keep the transport zone from the export unchanged.

.PARAMETER Disconnected
    Import the selected segments without a gateway connection (removes
    connectivity_path, keeps subnets) and skip the overlay gateway/subnet
    prompts. The summary lists the gateway each segment had on the source
    (Tier-1 renamed per the CSV), for connecting it at the cutover.

.PARAMETER SegmentFilter
    Wildcard applied to the exported segments' display_name before the
    selection menu appears. Default: '*' (all segments in the export).

.PARAMETER UpdateExisting
    PATCH selected segments and profiles that already exist on the target
    (same id) instead of skipping them. A PATCH merges the exported settings
    into the existing object.

.PARAMETER SkipCertCheck
    Bypass TLS certificate validation. Use for self-signed certificates.
    For internal CA certificates, import the CA root into the Windows Trusted
    Root store instead: Import-Certificate -FilePath ca.cer
    -CertStoreLocation Cert:\LocalMachine\Root

.EXAMPLE
    # Standard import - CSV auto-discovered next to the JSON
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -InputPath ./nsx-export_20260101_120000.json -SkipCertCheck

.EXAMPLE
    # Override transport zone and supply the CSV explicitly
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -InputPath ./exports/prod-migration.json `
        -MappingPath ./exports/prod-migration.csv `
        -TransportZoneId tz-overlay-prod `
        -SkipCertCheck

.EXAMPLE
    # Side-by-side without HCX: create the segments disconnected, connect
    # them to the target Tier-1 at the cutover
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -InputPath ./nsx-export_20260101_120000.json -Disconnected -WhatIf

.EXAMPLE
    # Dry run - preview all changes without touching NSX
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -InputPath ./nsx-export_20260101_120000.json -WhatIf

.NOTES
    Version : 2.7
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Pair    : Export-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
    GitHub  : https://github.com/pauldiee/nsx-segment-migration

    Changelog
    ---------
    2.7 - Scale and safety (#10): segments and profiles that already exist
          on the target are listed and skipped (a PATCH merged into them
          without a word); -UpdateExisting PATCHes them anyway. Failed
          binding maps count as errors and get their own summary line.
          Error list shows NSX's error_message (was empty). Exit codes 0 /
          1 / 2. Running count [n/total] per segment, per-object detail
          moved to -Verbose. Tier-1 remap replaces only the Tier-1 part of
          the path, literally. Get-AllPages no longer grows an array with +=.
          -SegmentFilter as on Export and Remove. Segment picker as in
          VIFolderManager/VITagManager: filter on the whole line (wildcard or
          /text: /VLAN, /T1:<name>, /TZ:<name>), 'reset', 'list', 'all',
          'cancel'; long lists are shortened.
    2.6 - Get-Help shows the full help again: blank line between
          #Requires and the help block (without it Get-Help ignored
          the whole help block).
    2.5 - Overlay validation runs for every overlay transport zone type
          (OVERLAY_BACKED, OVERLAY_STANDARD, OVERLAY_ENS); it was skipped
          for OVERLAY_STANDARD, the type of NSX 4's default overlay zone (#5).
    2.4 - Prompts without console input stop with a clear message instead
          of failing on .Trim() of $null. Credentials are saved in
          creds\<manager>.cred next to the script; the old file in the user
          profile is still read. -WhatIf lists the binding maps it would
          write and ends with a dry-run summary (#3).
    2.3 - Added -Disconnected: imports the selected segments without a
          gateway connection (connectivity_path removed, subnets kept),
          skips the overlay gateway/subnet prompts, and ends with a list of
          the gateway to connect each segment to at the cutover. Replaces
          editing the export JSON by hand (#1).
    2.2 - Added built-in credential save/reset via Resolve-Credential.
          Replaced Get-Credential with Read-Host to fix null credential errors
          in non-interactive PowerShell hosts under Set-StrictMode.
          Added $ScriptMeta branding banner (Name, Author, Blog, Date).
    2.1 - Added interactive transport zone selection menu after connecting.
          Added overlay segment validation: prompts for missing gateway and
          subnet before import begins when OVERLAY_BACKED TZ is selected.
          Added Get-AvailableGateways and Confirm-OverlaySegmentConfig.
    2.0 - Full rewrite. Clean comments, consistent style.
          Profile binding maps imported via typed child paths.
          NSX 4.x and 9.x profile path formats handled automatically.
          Profile path remap table ensures binding maps reference correct paths.
          Cursor-based pagination via Get-AllPages.
    1.x - Initial versions. Interactive segment selection. CSV name-mapping.
          WhatIf support. Transport zone override via -TransportZoneId.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$NSXManager,

    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory)]
    [string]$InputPath,

    [string]$MappingPath,

    [string]$TransportZoneId,

    [switch]$Disconnected,

    [switch]$UpdateExisting,

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
    param([string]$Path, [string]$Method = 'GET', [string]$Body)
    $params = @{
        Uri             = "https://$NSXManager$Path"
        Method          = $Method
        Headers         = $script:Headers
        UseBasicParsing = $true
    }
    if ($Body) { $params['Body'] = $Body }
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

function Get-TargetProfiles {
    # Lists the segment profiles on the target per type, from whichever path
    # format answers (NSX 9 flat first, then NSX 4). Returns a hashtable
    # "<type>|<id>" -> path on the target (#10).
    $found = @{}
    foreach ($ptype in 'qos-profiles', 'spoofguard-profiles', 'ip-discovery-profiles',
                       'mac-discovery-profiles', 'segment-security-profiles') {
        foreach ($base in "/policy/api/v1/infra/$ptype", "/policy/api/v1/infra/segment-profiles/$ptype") {
            try {
                foreach ($p in (Get-AllPages -Path $base)) {
                    $path = if ($p.PSObject.Properties['path']) { $p.path } else { ($base -replace '^/policy/api/v1', '') + "/$($p.id)" }
                    $found["$ptype|$($p.id)"] = $path
                }
                break
            } catch { Write-Verbose "[$ptype] not available at $base" }
        }
    }
    return $found
}

function Remove-ReadOnlyFields {
    # Strips NSX server-managed fields from an object before sending it in a PATCH.
    # NSX rejects requests that include any of these fields.
    param($Obj)
    $readOnly = @(
        'path', 'relative_path', 'parent_path', 'remote_path',
        'marked_for_delete', 'overridden', 'unique_id', 'realization_id',
        'owner_id', 'mac_pool_id',
        '_create_time', '_create_user',
        '_last_modified_time', '_last_modified_user',
        '_system_owned', '_protection', '_revision'
    )
    foreach ($field in $readOnly) {
        $Obj.PSObject.Properties.Remove($field) 2>$null
    }
    return $Obj
}

function Import-NameMapping {
    # Reads the CSV and returns a hashtable of hashtables:
    #   $map['Segment']['OldName']        = 'NewName'
    #   $map['SegmentProfile']['OldName'] = 'NewName'
    #   $map['T1Gateway']['OldName']      = 'NewName'
    # Only rows where NewName differs from OldName are stored. A missing key
    # means "no rename" - callers check ContainsKey before applying a rename.
    param([string]$CsvPath)

    $map = @{ Segment = @{}; SegmentProfile = @{}; T1Gateway = @{} }

    if (-not (Test-Path $CsvPath)) {
        Write-Warning "      CSV not found at '$CsvPath' - all names will be kept as-is"
        return $map
    }

    $changes = 0
    $kept    = 0

    foreach ($row in (Import-Csv $CsvPath)) {
        $type    = $row.Type.Trim()
        $oldName = $row.OldName.Trim()
        $newName = $row.NewName.Trim()

        if (-not $map.ContainsKey($type)) {
            Write-Warning "      Unknown type '$type' in CSV row - skipped"
            continue
        }
        if (-not $oldName) { continue }

        if ($newName -and $newName -ne $oldName) {
            $map[$type][$oldName] = $newName
            # The first 20 on screen, the rest with -Verbose (#10)
            if ($changes -lt 20) { Write-Host "      [RENAME] $type '$oldName' -> '$newName'" }
            else { Write-Verbose "      [RENAME] $type '$oldName' -> '$newName'" }
            $changes++
        } else {
            $kept++
        }
    }

    if ($changes -gt 20) { Write-Host "      ... and $($changes - 20) more (all with -Verbose)" }
    Write-Host "      $changes rename(s) loaded, $kept object(s) keeping their existing name"
    return $map
}

function Resolve-Name {
    # Applies a rename from the CSV map to an object's display_name and id.
    # If no entry exists for this object the object is returned unchanged.
    param($Obj, [string]$Type, [hashtable]$Map)
    $oldName = $Obj.display_name
    if ($Map[$Type].ContainsKey($oldName)) {
        $newName          = $Map[$Type][$oldName]
        $Obj.display_name = $newName
        $Obj.id           = $newName
        Write-Verbose "      [RENAME] $Type '$oldName' -> '$newName'"
    }
    return $Obj
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
    return Select-FromList -Items $Segments -Title 'SELECT SEGMENTS TO IMPORT' -LineText { param($s) Get-SegmentLine -Seg $s }
}

function Select-TransportZone {
    # Fetches all transport zones from the target NSX and presents a numbered
    # selection menu. Returns a PSCustomObject with 'id' and 'tz_type' properties,
    # or $null if the operator presses Enter to keep the source transport zone.
    $tzPath = '/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones'
    try {
        $allTzs = @(Get-AllPages -Path $tzPath)
    } catch {
        Write-Warning "      Could not fetch transport zones: $_"
        return $null
    }

    if ($allTzs.Count -eq 0) {
        Write-Warning "      No transport zones found on target NSX"
        return $null
    }

    $sorted = @($allTzs | Sort-Object display_name)
    $total  = $sorted.Count

    Write-Host ""
    Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "|  SELECT TARGET TRANSPORT ZONE                    |" -ForegroundColor Yellow
    Write-Host "|  Applied to all imported segments.               |" -ForegroundColor Yellow
    Write-Host "|  Press Enter to keep the TZ from the export.    |" -ForegroundColor Yellow
    Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""

    for ($i = 0; $i -lt $total; $i++) {
        $tz   = $sorted[$i]
        $num  = ($i + 1).ToString().PadLeft($total.ToString().Length)
        $type = if ($tz.PSObject.Properties['tz_type'] -and $tz.tz_type) { $tz.tz_type } else { 'UNKNOWN' }
        Write-Host ("  [{0}] {1}  [{2}]" -f $num, $tz.display_name, $type)
    }

    Write-Host ""

    while ($true) {
        $raw = Read-Answer "  Select (or Enter to keep existing)"

        if (-not $raw) {
            Write-Host "  Keeping transport zone from export" -ForegroundColor Gray
            Write-Host ""
            return $null
        }

        if ($raw -match '^\d+$') {
            $n = [int]$raw
            if ($n -ge 1 -and $n -le $total) {
                $chosen = $sorted[$n - 1]
                $type   = if ($chosen.PSObject.Properties['tz_type'] -and $chosen.tz_type) { $chosen.tz_type } else { 'UNKNOWN' }
                Write-Host "  Selected: $($chosen.display_name)  [$type]" -ForegroundColor Green
                Write-Host ""
                return [PSCustomObject]@{ id = $chosen.id; tz_type = $type }
            }
        }

        Write-Host "  Invalid selection - enter a number between 1 and $total, or press Enter to skip" -ForegroundColor Red
    }
}

function Get-AvailableGateways {
    # Returns a sorted list of all T0 and T1 gateways from the target NSX.
    # Used by Confirm-OverlaySegmentConfig to let the operator pick a gateway
    # for segments that have no connectivity_path set.
    $gateways = @()
    foreach ($pair in @(
        @{ path = '/policy/api/v1/infra/tier-1s'; tier = 'T1' },
        @{ path = '/policy/api/v1/infra/tier-0s'; tier = 'T0' }
    )) {
        try {
            $items = @(Get-AllPages -Path $pair.path)
            foreach ($gw in $items) {
                $gateways += [PSCustomObject]@{
                    id           = $gw.id
                    display_name = $gw.display_name
                    tier         = $pair.tier
                    path         = $gw.path
                }
            }
        } catch {
            Write-Verbose "Could not fetch gateways from $($pair.path)"
        }
    }
    return @($gateways | Sort-Object tier, display_name)
}

function Confirm-OverlaySegmentConfig {
    # Validates that each segment has the two fields required by NSX for
    # overlay-backed segments: connectivity_path (gateway) and subnets (IP).
    # If either is missing the operator is prompted to supply it interactively.
    # Pressing Enter at any prompt skips that field - the segment is then
    # imported without it (NSX accepts disconnected overlay segments).
    # Returns the (possibly updated) array of segments.
    param([array]$Segments)

    # Fetch gateways once and reuse across all segments
    Write-Host "      Fetching available gateways on target NSX ..."
    $gateways = @(Get-AvailableGateways)
    if ($gateways.Count -gt 0) {
        Write-Host "      Found $($gateways.Count) gateway(s)"
    } else {
        Write-Warning "      No T0/T1 gateways found - gateway assignment will be skipped"
    }

    $updated = [System.Collections.Generic.List[object]]::new()

    foreach ($seg in $Segments) {
        # Deep-clone to avoid mutating the original object
        $s       = $seg | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $segName = $s.display_name

        Write-Host ""
        Write-Host "  --- Overlay config: '$segName' ---" -ForegroundColor Cyan

        # ---- Gateway (connectivity_path) ------------------------------------
        $hasGateway = $s.PSObject.Properties['connectivity_path'] -and $s.connectivity_path
        if ($hasGateway) {
            Write-Host "  Gateway : $($s.connectivity_path)" -ForegroundColor Green
        } else {
            Write-Host "  Gateway : not set" -ForegroundColor Yellow

            if ($gateways.Count -gt 0) {
                Write-Host ""
                Write-Host "  Available gateways:"
                for ($i = 0; $i -lt $gateways.Count; $i++) {
                    $gw  = $gateways[$i]
                    $num = ($i + 1).ToString().PadLeft($gateways.Count.ToString().Length)
                    Write-Host ("    [{0}] [{1}] {2}" -f $num, $gw.tier, $gw.display_name)
                }
                Write-Host "    [Enter] Leave unconnected (disconnected overlay segment)"
                Write-Host ""

                while ($true) {
                    $raw = Read-Answer "  Gateway for '$segName'"
                    if (-not $raw) {
                        Write-Host "  Leaving segment disconnected" -ForegroundColor Gray
                        break
                    }
                    if ($raw -match '^\d+$') {
                        $n = [int]$raw
                        if ($n -ge 1 -and $n -le $gateways.Count) {
                            $chosen = $gateways[$n - 1]
                            $s | Add-Member -MemberType NoteProperty -Name 'connectivity_path' -Value $chosen.path -Force
                            Write-Host "  Gateway set: $($chosen.display_name)" -ForegroundColor Green
                            break
                        }
                    }
                    Write-Host "  Invalid selection" -ForegroundColor Red
                }
            } else {
                Write-Host "  No gateways available - segment will be imported disconnected" -ForegroundColor Yellow
            }
        }

        # ---- Subnet (subnets[].gateway_address) ----------------------------
        $hasSubnet = $s.PSObject.Properties['subnets'] -and $s.subnets -and @($s.subnets).Count -gt 0
        if ($hasSubnet) {
            $subnetStr = (@($s.subnets) | ForEach-Object {
                if ($_.PSObject.Properties['gateway_address']) { $_.gateway_address } else { '?' }
            }) -join ', '
            Write-Host "  Subnet  : $subnetStr" -ForegroundColor Green
        } else {
            Write-Host "  Subnet  : not set" -ForegroundColor Yellow
            Write-Host "  Enter subnet as gateway/prefix (e.g. 192.168.10.1/24),"
            Write-Host "  or press Enter to import without a subnet."
            Write-Host ""

            while ($true) {
                $raw = Read-Answer "  Subnet for '$segName'"
                if (-not $raw) {
                    Write-Host "  Skipping subnet" -ForegroundColor Gray
                    break
                }
                # Basic IPv4 CIDR validation
                if ($raw -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
                    $subnet = [PSCustomObject]@{ gateway_address = $raw }
                    $s | Add-Member -MemberType NoteProperty -Name 'subnets' -Value @($subnet) -Force
                    Write-Host "  Subnet set: $raw" -ForegroundColor Green
                    break
                }
                Write-Host "  Invalid format - use x.x.x.x/prefix (e.g. 192.168.10.1/24)" -ForegroundColor Red
            }
        }

        $updated.Add($s)
    }

    Write-Host ""
    return @($updated)
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
    Name    = "Import-NSXSegments.ps1"
    Version = "2.7"
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

# -- 1. Load export JSON ------------------------------------------------------
if (-not (Test-Path $InputPath)) { throw "Input file not found: $InputPath" }
Write-Host "`n[1/5] Loading export file: $InputPath" -ForegroundColor Cyan
$exportData = Get-Content $InputPath -Raw | ConvertFrom-Json

Write-Host "      Exported from : $($exportData.source_manager)"
Write-Host "      Export date   : $($exportData.export_timestamp)"
Write-Host "      Segments      : $(@($exportData.segments).Count)"
Write-Host "      Profiles      : $(@($exportData.segment_profiles).Count)"

# -- 2. Load CSV name-mapping -------------------------------------------------
# Loaded before the selection menu so rename information is available when
# building the profile path remap table immediately after selection.
if (-not $MappingPath) {
    $MappingPath = [System.IO.Path]::ChangeExtension($InputPath, '.csv')
}
Write-Host "`n[2/5] Loading name mappings from: $MappingPath" -ForegroundColor Cyan
$nameMap = Import-NameMapping -CsvPath $MappingPath

# Interactive segment selection, after -SegmentFilter on the name (#10)
$allExported = @($exportData.segments)
$filtered    = @($allExported | Where-Object { $_.display_name -like $SegmentFilter })
if ($SegmentFilter -ne '*') {
    Write-Host "      $($filtered.Count) of $($allExported.Count) segment(s) match '$SegmentFilter'"
}
if ($filtered.Count -eq 0) {
    Write-Warning "No segments in the export match '$SegmentFilter'. Nothing to import."
    exit 0
}
# Source transport zone names from the export (Export 2.4+), for the picker
if ($exportData.PSObject.Properties['transport_zone_names'] -and $exportData.transport_zone_names) {
    foreach ($p in $exportData.transport_zone_names.PSObject.Properties) { $script:TzNames[$p.Name] = "$($p.Value)" }
}
$selectedSegments = @(Select-Segments -Segments $filtered)
if ($selectedSegments.Count -eq 0) {
    if ($script:PickerCancelled) { Write-Host "  Nothing imported." -ForegroundColor Yellow }
    else { Write-Warning "No segments selected. Nothing to import." }
    exit 0
}

# Build a profile path remap table covering ALL profiles in the export.
# This table translates source NSX profile paths to target NSX profile paths,
# including any renames applied via the CSV.
#
# It is pre-populated here with the expected target paths (flat NSX 9 format).
# After each profile PATCH in step 4 the table is updated with the path that
# actually succeeded, so binding maps always reference a path known to exist.
$profilePathRemap = @{}
foreach ($prof in @($exportData.segment_profiles)) {
    if (-not $prof.PSObject.Properties['path']) { continue }
    $oldPath = $prof.path

    # Extract type and id from either path format:
    #   NSX 4:  /infra/segment-profiles/<type>/<id>
    #   NSX 9:  /infra/<type>/<id>
    if ($oldPath -match '^/infra/segment-profiles/([^/]+)/([^/]+)$') {
        $ptype = $Matches[1]; $profId = $Matches[2]
    } elseif ($oldPath -match '^/infra/([^/]+)/([^/]+)$') {
        $ptype = $Matches[1]; $profId = $Matches[2]
    } else {
        $profilePathRemap[$oldPath] = $oldPath
        continue
    }

    $displayName = if ($prof.PSObject.Properties['display_name']) { $prof.display_name } else { $profId }
    $newId = if ($nameMap['SegmentProfile'].ContainsKey($displayName)) {
        $nameMap['SegmentProfile'][$displayName]
    } else { $profId }

    $newPathFlat   = "/infra/$ptype/$newId"
    $newPathLegacy = "/infra/segment-profiles/$ptype/$newId"

    # Register all known path variants pointing at the expected flat target path.
    # Whichever actually succeeds during PATCH will update these entries.
    $profilePathRemap[$oldPath]                                 = $newPathFlat
    $profilePathRemap["/infra/segment-profiles/$ptype/$profId"] = $newPathFlat
    $profilePathRemap["/infra/$ptype/$profId"]                  = $newPathFlat
}

# Import all profiles regardless of segment selection. PATCH is idempotent so
# re-creating an existing profile is harmless, and this avoids any risk of a
# segment referencing a profile that was skipped.
$profilesToImport = @($exportData.segment_profiles)
Write-Host "      Profiles to import: $($profilesToImport.Count)"

# Load binding map entries. Structure in the JSON:
#   segment_binding_maps: { "<segmentId>": [ { bmtype, data }, ... ] }
# Keyed by segment id (before any rename) so lookups use the original id.
$exportBindingMaps = @{}
if ($exportData.PSObject.Properties['segment_binding_maps'] -and
    $exportData.segment_binding_maps) {
    foreach ($prop in $exportData.segment_binding_maps.PSObject.Properties) {
        $exportBindingMaps[$prop.Name] = @($prop.Value)
    }
}
Write-Host "      Segments with binding maps: $($exportBindingMaps.Count)"

# -- 3. Connect and transport zone selection ----------------------------------
$Credential = Resolve-Credential -Supplied $Credential -Manager $NSXManager
if ($SkipCertCheck -and $PSVersionTable.PSVersion.Major -lt 6) { Set-TlsSkipCert }
$script:Headers = Get-BasicAuthHeader -Cred $Credential

Write-Host "`n[3/5] Verifying connectivity to $NSXManager ..." -ForegroundColor Cyan
$ver = Invoke-NSXApi -Path '/api/v1/node/version'
Write-Host "      NSX version : $($ver.product_version)" -ForegroundColor Green

# Determine transport zone id and type.
# The tz_type drives whether overlay validation is needed in the next step.
if (-not $TransportZoneId) {
    # Interactive picker - returns { id, tz_type } or $null to keep source TZ
    $tzSelection = Select-TransportZone
    if ($tzSelection) {
        $TransportZoneId       = $tzSelection.id
        $script:SelectedTzType = $tzSelection.tz_type
    } else {
        # Operator pressed Enter - source TZ id is kept on each segment.
        # Type is unknown at this point; validation is skipped to be safe.
        $script:SelectedTzType = 'KEEP'
    }
} else {
    # TZ supplied on the command line - look up its type from the target NSX
    # so we know whether overlay validation is needed.
    try {
        $tzObj = Invoke-NSXApi -Path "/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones/$TransportZoneId"
        $script:SelectedTzType = if ($tzObj.PSObject.Properties['tz_type']) { $tzObj.tz_type } else { 'UNKNOWN' }
    } catch {
        Write-Warning "      Could not look up type for TZ '$TransportZoneId' - overlay validation skipped"
        $script:SelectedTzType = 'UNKNOWN'
    }
}
Write-Host "      Transport zone type: $($script:SelectedTzType)"

# For overlay-backed transport zones, check each selected segment for the two
# fields that NSX requires: a gateway connection and a subnet. Any that are
# missing trigger an interactive prompt so the operator can supply them before
# the import begins. VLAN-backed segments skip this step entirely.
if ($Disconnected) {
    Write-Host "`n      -Disconnected: segments are imported without a gateway connection;" -ForegroundColor Cyan
    Write-Host "      overlay gateway/subnet check skipped (subnets from the export are kept)." -ForegroundColor Cyan
} elseif ($script:SelectedTzType -like 'OVERLAY*') {   # OVERLAY_BACKED / _STANDARD / _ENS (#5)
    Write-Host "`n      Checking overlay segment requirements ..." -ForegroundColor Cyan
    $selectedSegments = @(Confirm-OverlaySegmentConfig -Segments $selectedSegments)
}
$disconnectedList = [System.Collections.Generic.List[object]]::new()

# What already exists on the target (#10). PATCH merges into an existing
# object with the same id, so without this check an import would silently
# change a segment or profile that is already there. Existing objects are
# skipped unless -UpdateExisting.
Write-Host "`n      Checking the target for segments and profiles that already exist ..." -ForegroundColor Cyan
$targetSegIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($ts in (Get-AllPages -Path '/policy/api/v1/infra/segments')) { [void]$targetSegIds.Add($ts.id) }
$targetProfiles = Get-TargetProfiles

function Get-TargetId {
    # The id an object gets on the target: the CSV's NewName when renamed, else its own id
    param($Obj, [string]$Type)
    $dn = if ($Obj.PSObject.Properties['display_name']) { $Obj.display_name } else { '' }
    if ($dn -and $nameMap[$Type].ContainsKey($dn)) { return $nameMap[$Type][$dn] }
    return $Obj.id
}
function Get-ProfileType {
    param([string]$Path)
    if ($Path -match '/segment-profiles/([^/]+)/[^/]+$') { return $Matches[1] }
    if ($Path -match '/infra/([^/]+)/[^/]+$') { return $Matches[1] }
    return $null
}

$existingSegs = @($selectedSegments | Where-Object { $targetSegIds.Contains((Get-TargetId -Obj $_ -Type 'Segment')) })
$existingProfiles = @($profilesToImport | Where-Object {
    $pt = Get-ProfileType -Path $_.path
    $pt -and $targetProfiles.ContainsKey("$pt|$(Get-TargetId -Obj $_ -Type 'SegmentProfile')")
})
$existingSegIdSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($e in $existingSegs) { [void]$existingSegIdSet.Add((Get-TargetId -Obj $e -Type 'Segment')) }

if ($existingSegs.Count -eq 0 -and $existingProfiles.Count -eq 0) {
    Write-Host "      None of the selected segments or profiles exist on the target yet."
} else {
    $action = if ($UpdateExisting) { 'updated (PATCH, -UpdateExisting)' } else { 'skipped; pass -UpdateExisting to PATCH them anyway' }
    Write-Host "      Already on the target, $($action):" -ForegroundColor Yellow
    $shown = 0
    foreach ($e in $existingProfiles) { if ($shown -lt 20) { Write-Host "        profile  $(Get-TargetId -Obj $e -Type 'SegmentProfile')" -ForegroundColor Yellow }; $shown++ }
    foreach ($e in $existingSegs)     { if ($shown -lt 20) { Write-Host "        segment  $(Get-TargetId -Obj $e -Type 'Segment')" -ForegroundColor Yellow }; $shown++ }
    if ($shown -gt 20) { Write-Host "        ... and $($shown - 20) more" -ForegroundColor Yellow }
    Write-Host "      ($($existingProfiles.Count) profile(s), $($existingSegs.Count) segment(s))" -ForegroundColor Yellow
}

# -- 4. Import segment profiles -----------------------------------------------
Write-Host "`n[4/5] Importing custom segment profiles ..." -ForegroundColor Cyan

$okProfiles    = 0
$errProfiles   = 0
$wouldProfiles = 0
$skipProfiles  = 0
$errList       = [System.Collections.Generic.List[string]]::new()

foreach ($profile in $profilesToImport) {

    $p       = $profile | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $oldPath = $p.path

    # Resolve profile type from path (handles both NSX 4 and NSX 9 formats)
    if ($oldPath -match '/segment-profiles/([^/]+)/[^/]+$') {
        $ptype = $Matches[1]
    } elseif ($oldPath -match '/infra/([^/]+)/[^/]+$') {
        $ptype = $Matches[1]
    } else {
        Write-Warning "      Cannot determine profile type from path '$oldPath' - skipping"
        $errProfiles++; continue
    }

    $p     = Resolve-Name -Obj $p -Type 'SegmentProfile' -Map $nameMap
    $newId = $p.id

    # Build both path formats for this profile on the target NSX.
    # Try NSX 9 flat path first, then fall back to NSX 4 legacy path.
    $newPathFlat   = "/infra/$ptype/$newId"
    $newPathLegacy = "/infra/segment-profiles/$ptype/$newId"

    # Already on the target: keep it as it is (unless -UpdateExisting) and
    # point the binding maps at the path it has there (#10)
    if ($targetProfiles.ContainsKey("$ptype|$newId") -and -not $UpdateExisting) {
        $existingPath = $targetProfiles["$ptype|$newId"]
        $profilePathRemap[$oldPath]       = $existingPath
        $profilePathRemap[$newPathFlat]   = $existingPath
        $profilePathRemap[$newPathLegacy] = $existingPath
        Write-Host "      [EXISTS] $($p.display_name)  ($existingPath, left as is)" -ForegroundColor Yellow
        $skipProfiles++
        continue
    }
    $p             = Remove-ReadOnlyFields -Obj $p
    $body          = $p | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess($NSXManager, "PATCH profile '$($p.display_name)'")) {
        $written = $false
        $lastProfileError = ''
        foreach ($tryPath in @("/policy/api/v1$newPathFlat", "/policy/api/v1$newPathLegacy")) {
            try {
                $null = Invoke-NSXApi -Path $tryPath -Method PATCH -Body $body
                $successPath = $tryPath -replace '^/policy/api/v1', ''
                # Update the remap table with the confirmed working path so that
                # binding maps written in step 5 reference a path that exists.
                $profilePathRemap[$oldPath]      = $successPath
                $profilePathRemap[$newPathFlat]   = $successPath
                $profilePathRemap[$newPathLegacy] = $successPath
                Write-Host "      [OK] $($p.display_name)  ->  $successPath" -ForegroundColor Green
                $okProfiles++; $written = $true; break
            } catch {
                $lastProfileError += "[$($tryPath -replace '^/policy/api/v1', '')] $_ "
                Write-Verbose "      $tryPath failed ($_), trying next..."
            }
        }
        if (-not $written) {
            Write-Warning "      [FAIL] $($p.display_name) - could not be written to any API path: $lastProfileError"
            $errList.Add("Profile '$($profile.display_name)': $lastProfileError")
            $errProfiles++
        }
    } else {
        Write-Host "      [WhatIf] Would PATCH profile '$($p.display_name)'"
        $wouldProfiles++
    }
}

# -- 5. Import segments and profile binding maps ------------------------------
Write-Host "`n[5/5] Importing segments ..." -ForegroundColor Cyan

$okSegments    = 0
$errSegments   = 0
$wouldSegments = 0
$skipSegments  = 0
$okBindings    = 0
$errBindings   = 0
$wouldBindings = 0
$segNo         = 0
$segTotal      = $selectedSegments.Count
if ($TransportZoneId) { Write-Host "      [TZ] $TransportZoneId applied to every imported segment" }

foreach ($segment in $selectedSegments) {
    $segNo++
    $counter = "[$segNo/$segTotal]"
    Write-Progress -Activity 'Importing segments' -Status "$segNo of $segTotal" -PercentComplete ([int](100 * $segNo / $segTotal))

    # Deep-clone so we never mutate the in-memory export data
    $s       = $segment | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $oldName = $s.display_name
    $oldId   = $s.id   # preserve the original id for binding map lookup after rename

    $s = Resolve-Name -Obj $s -Type 'Segment' -Map $nameMap

    # Already on the target: leave it alone unless -UpdateExisting (#10)
    if ($existingSegIdSet.Contains($s.id) -and -not $UpdateExisting) {
        Write-Host "      $counter [EXISTS] $($s.display_name) - left as is" -ForegroundColor Yellow
        $skipSegments++
        continue
    }

    # -Disconnected: drop the gateway connection, keep the subnets. Remember
    # the gateway to connect at the cutover (source gateway after the CSV T1
    # remap, so a renamed Tier-1 shows its target name) for the summary list.
    if ($Disconnected) {
        $srcGw = ''
        if ($s.PSObject.Properties['connectivity_path'] -and $s.connectivity_path) {
            $srcGw = "$($s.connectivity_path)"
            if ($srcGw -match '/tier-1s/([^/]+)' -and $nameMap['T1Gateway'].ContainsKey($Matches[1])) {
                $srcGw = $srcGw -replace [regex]::Escape($Matches[1]), $nameMap['T1Gateway'][$Matches[1]]
            }
            $s.PSObject.Properties.Remove('connectivity_path')
            Write-Verbose "      [DISCONNECTED] '$($s.display_name)' (connect at cutover: $srcGw)"
        }
        $subnetStr = ''
        if ($s.PSObject.Properties['subnets'] -and $s.subnets) {
            $subnetStr = (@($s.subnets) | ForEach-Object {
                if ($_.PSObject.Properties['gateway_address']) { $_.gateway_address }
            }) -join ', '
        }
        $disconnectedList.Add([PSCustomObject]@{
            Segment = $s.display_name
            ConnectAtCutover = if ($srcGw) { $srcGw } else { '(none)' }
            Subnets = if ($subnetStr) { $subnetStr } else { '(none)' }
        })
    }

    # Remap T1 gateway reference if the CSV maps this gateway to a different id
    # on the target NSX (T0 gateways use a different path prefix - not remapped here)
    if ($s.PSObject.Properties['connectivity_path'] -and $s.connectivity_path -and
        $s.connectivity_path -match '/tier-1s/([^/]+)') {
        $oldT1 = $Matches[1]
        if ($nameMap['T1Gateway'].ContainsKey($oldT1)) {
            $newT1               = $nameMap['T1Gateway'][$oldT1]
            # Replace only the Tier-1 segment of the path; a literal replacement
            # so a '$' in the new id is not read as a regex group (#10)
            $s.connectivity_path = $s.connectivity_path.Replace("/tier-1s/$oldT1", "/tier-1s/$newT1")
            Write-Verbose "      [REMAP T1] '$oldT1' -> '$newT1'"
        }
    }

    # Apply transport zone override if one was selected or supplied
    if ($TransportZoneId) {
        $s.transport_zone_path = "/infra/sites/default/enforcement-points/default/transport-zones/$TransportZoneId"
    }

    $s       = Remove-ReadOnlyFields -Obj $s
    $segId   = $s.id
    $apiPath = "/policy/api/v1/infra/segments/$segId"
    $body    = $s | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess($NSXManager, "PATCH segment '$($s.display_name)'")) {
        $was = if ($oldName -ne $s.display_name) { " (was $oldName)" } else { '' }
        try {
            $null = Invoke-NSXApi -Path $apiPath -Method PATCH -Body $body
            Write-Host "      $counter [OK] $($s.display_name)$was" -ForegroundColor Green
            $okSegments++
        } catch {
            Write-Warning "      $counter [FAIL] $($s.display_name)$($was): $_"
            $errList.Add("Segment '$oldName': $_")
            $errSegments++
            continue   # skip binding maps - no point applying them if the segment failed
        }
    } else {
        Write-Host "      $counter [WhatIf] Would PATCH segment '$($s.display_name)' at $apiPath"
        $wouldSegments++
    }

    # Apply profile binding maps for this segment (in a dry run: list them).
    # The export keys binding maps by the original segment id (before any rename)
    # so we look up by $oldId first, then fall back to $segId (the post-rename id)
    # for exports produced before renaming was introduced.
    $entryKey = if ($exportBindingMaps.ContainsKey($oldId))   { $oldId  }
                elseif ($exportBindingMaps.ContainsKey($segId)) { $segId  }
                else                                             { $null  }

    if ($entryKey) {
        $entries = @($exportBindingMaps[$entryKey])
        Write-Verbose "      Applying $($entries.Count) profile binding(s)"

        foreach ($entry in $entries) {
            # Each entry carries the binding map type (which child API path to use)
            # and the raw binding map data object from the export.
            $bmType = if ($entry.PSObject.Properties['bmtype']) { $entry.bmtype } else { 'segment-discovery-profile-binding-maps' }
            $bm     = if ($entry.PSObject.Properties['data'])   { $entry.data   } else { $entry }

            $b       = $bm | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            $bmOldId = if ($b.PSObject.Properties['id']) { $b.id } else { 'default' }

            # Translate every *_profile_path property through the remap table.
            # This updates qos_profile_path, ip_discovery_profile_path, etc.
            # to point at the correctly named profile on the target NSX.
            foreach ($prop in @($b.PSObject.Properties)) {
                if ($prop.Name -match '_profile_path$' -and
                    $prop.Value -is [string] -and
                    $profilePathRemap.ContainsKey($prop.Value)) {
                    $newVal = $profilePathRemap[$prop.Value]
                    Write-Verbose "        [REMAP] $($prop.Name): $($prop.Value) -> $newVal"
                    $b.$($prop.Name) = $newVal
                }
            }

            $b         = Remove-ReadOnlyFields -Obj $b
            $bmId      = if ($b.PSObject.Properties['id']) { $b.id } else { 'default' }
            $bmApiPath = "/policy/api/v1/infra/segments/$segId/$bmType/$bmId"
            $bmBody    = $b | ConvertTo-Json -Depth 20

            if ($PSCmdlet.ShouldProcess($NSXManager, "PATCH $bmType on '$($s.display_name)'")) {
                try {
                    $null = Invoke-NSXApi -Path $bmApiPath -Method PATCH -Body $bmBody
                    Write-Host "        [OK] $bmType/$bmId" -ForegroundColor Green
                    $okBindings++
                } catch {
                    # Counted as an error (#10): the segment exists but misses a profile
                    Write-Warning "        [FAIL] $bmType/$bmId : $_"
                    $errList.Add("$bmType '$bmOldId' on segment '$oldName': $_")
                    $errBindings++
                }
            } else {
                Write-Host "        [WhatIf] Would PATCH $bmApiPath"
                $wouldBindings++
            }
        }
    } else {
        Write-Verbose "      No profile bindings in export for '$oldName'"
    }
}
Write-Progress -Activity 'Importing segments' -Completed

# -- Summary ------------------------------------------------------------------
$totalErrors = $errProfiles + $errSegments + $errBindings
$statusColor = if ($totalErrors -eq 0) { 'Green' } else { 'Yellow' }
$dryRun      = [bool]$WhatIfPreference

if ($dryRun) {
    Write-Host @"

+==================================================+
|   DRY RUN (-WhatIf): nothing was changed         |
+==================================================+
|  Profiles that would be written : $("$wouldProfiles".PadRight(15))|
|  Segments that would be written : $("$wouldSegments".PadRight(15))|
|  Bindings that would be written : $("$wouldBindings".PadRight(15))|
|  Profiles already on target     : $("$skipProfiles".PadRight(15))|
|  Segments already on target     : $("$skipSegments".PadRight(15))|
+==================================================+
"@ -ForegroundColor Cyan
} else {
Write-Host @"

+==================================================+
|   IMPORT SUMMARY                                 |
+==================================================+
|  Profiles  OK / Failed : $("$okProfiles / $errProfiles".PadRight(24))|
|  Segments  OK / Failed : $("$okSegments / $errSegments".PadRight(24))|
|  Bindings  OK / Failed : $("$okBindings / $errBindings".PadRight(24))|
|  Skipped (on target)   : $("$skipProfiles prof. / $skipSegments seg.".PadRight(24))|
+==================================================+
"@ -ForegroundColor $statusColor
}

if ($disconnectedList.Count -gt 0) {
    $verb = if ($dryRun) { 'Would be imported' } else { 'Imported' }
    Write-Host "`n$verb without a gateway (-Disconnected). Connect these at the cutover;" -ForegroundColor Cyan
    Write-Host "ConnectAtCutover is the source gateway, with Tier-1 names after the CSV remap:" -ForegroundColor Cyan
    $disconnectedList | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
}

if ($errList.Count -gt 0) {
    Write-Host "`nErrors:" -ForegroundColor Red
    $errList | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} elseif ($dryRun) {
    Write-Host "Dry run complete. Run again without -WhatIf to import.`n" -ForegroundColor Cyan
} else {
    Write-Host "All items imported successfully!`n" -ForegroundColor Green
}

# Exit codes (#10): 0 success (or dry run), 1 fatal error (thrown), 2 finished with errors
if ($totalErrors -gt 0) { exit 2 }
exit 0
