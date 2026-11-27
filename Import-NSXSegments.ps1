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
    in <manager>.cred next to the scripts (encrypted with DPAPI on
    Windows, not encrypted on Linux and macOS). On
    subsequent runs a menu offers to reuse, overwrite, or ignore the saved
    credential. Pass -Credential to bypass the interactive flow entirely.

    Transport zone selection
    ------------------------
    After connecting, an interactive menu lists all available transport zones.
    The selected TZ is applied to all imported segments. Press Enter to keep
    the transport zone from the export unchanged. Supply -TransportZoneId to
    skip the menu entirely (useful for automation), or -KeepSourceTransportZone
    to keep the zone from the export without the menu.

    When the export comes from another NSX Manager (its source_manager differs
    from -NSXManager), Enter does not keep the source zone: the menu says where
    the segments would land (the zone with the same id on the target, or none)
    and asks for a number or KEEP. NSX's own default zones have the same id on
    every manager tested, so a kept zone can be the target's default zone,
    which the hosts of a VCF domain don't use. The summary names the zone used.

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
    FQDN or IP address of the target NSX Manager. If omitted, the script asks
    for it and lists the managers with a saved credential.

.PARAMETER Credential
    PSCredential for the NSX Manager admin account.
    If omitted, the built-in credential manager handles prompting and saving.

.PARAMETER InputPath
    Path to the .json file produced by Export-NSXSegments.ps1. If omitted,
    the script lists the exports in the current folder and the script folder.
    The companion .csv is expected at the same path with a .csv extension
    unless -MappingPath is specified.

.PARAMETER MappingPath
    Optional explicit path to the CSV name-mapping file.

.PARAMETER TransportZoneId
    Transport zone id to apply to all imported segments. If omitted, an
    interactive menu lets you choose from the transport zones on the target NSX.
    Press Enter at the menu to keep the transport zone from the export unchanged
    (type KEEP when the export comes from another NSX Manager).

.PARAMETER KeepSourceTransportZone
    Keep the transport zone from the export on every segment, without the menu.
    When the export comes from another NSX Manager, the log shows where the
    segments land on the target. Can't be combined with -TransportZoneId.

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
    Version : 3.1
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Pair    : Export-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
    GitHub  : https://github.com/pauldiee/nsx-segment-migration

    Changelog
    ---------
    3.1 - Interactive start (#20): without -InputPath the script lists the
          exports in the current and the script folder (source manager,
          segments, profiles, date) to pick from; without -NSXManager it
          asks for the target (managers with a saved credential as
          numbers). The summary boxes fit their content, name the manager
          and include the transport zone used.
          The real error as one red ERROR: line instead of a PowerShell
          error record. An untrusted certificate without -SkipCertCheck:
          asks whether to go on without the check for this run. Saved
          credentials as <manager>.cred next to the scripts, as in the
          vCenter toolkits (creds\ and the profile file are still read).
          Needs NSXSM-Common.ps1 1.2.
    3.0 - Transport zone from another NSX Manager (#17): when the export's
          source_manager differs from -NSXManager, Enter at the transport
          zone menu no longer keeps the source zone silently. The menu says
          where the segments would land (the zone with the same id on the
          target, or none) and asks for a number or KEEP. Found in the lab:
          NSX's default zones have the same id on NSX 4.2.4.1 and 9.0.2, so
          Enter put a segment in the target's default overlay zone without
          an error. Same manager: Enter works as before. New switch
          -KeepSourceTransportZone keeps the source zone without the menu.
          The summary names the transport zone used.
    2.9 - Closing line from the counts (#13): "Nothing imported: ..." when
          everything selected was already on the target (or declined), and
          "Imported n segment(s) ...; m already on the target" when part of
          it was skipped. "All items imported successfully!" only when
          everything was written. Under -Confirm, No is reported as
          [DECLINED] and counted (it was shown as "[WhatIf] Would PATCH"),
          and a declined segment no longer asks for its binding maps. The
          -Disconnected cutover list holds only segments that were written
          (or would be, in a dry run); a declined or failed segment was
          listed as imported.
    2.8 - Shared helpers moved to NSXSM-Common.ps1 (#11), unchanged: REST
          calls, pickers, prompts and credentials. The script stops with a
          clear message when NSXSM-Common.ps1 is missing or older than 1.0;
          the banner shows its version. Commands and parameters are the same.
          Help: credentials are in creds\ next to the scripts (since #3),
          not in the user profile.
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
    [string]$NSXManager,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$InputPath,

    [string]$MappingPath,

    [string]$TransportZoneId,

    [switch]$KeepSourceTransportZone,

    [switch]$Disconnected,

    [switch]$UpdateExisting,

    [string]$SegmentFilter = '*',

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

function Select-Segments {
    # Segment picker (#10): see Select-FromList
    param([array]$Segments)
    return Select-FromList -Items $Segments -Title 'SELECT SEGMENTS TO IMPORT' -LineText { param($s) Get-SegmentLine -Seg $s }
}

function Get-ManagerKey {
    # Normalised manager name for comparing the export's source_manager with
    # the target (#17): lower case, without scheme, port or trailing slash.
    param([string]$Name)
    $n = "$Name".Trim().ToLowerInvariant()
    $n = $n -replace '^https?://', '' -replace '/+$', '' -replace ':\d+$', ''
    return $n
}

function Get-SourceTzLanding {
    # Where the selected segments land when their transport zone from the
    # export is kept (#17): per distinct source TZ id, the zone with that id on
    # the target, or 'not on the target'. Returns one line per zone.
    param([array]$Segments, [array]$TargetTzs)
    $lines = [System.Collections.Generic.List[string]]::new()
    $ids = @($Segments | ForEach-Object {
        if ($_.PSObject.Properties['transport_zone_path'] -and $_.transport_zone_path) { ($_.transport_zone_path -split '/')[-1] } else { '(none)' }
    } | Sort-Object -Unique)
    foreach ($id in $ids) {
        $count  = @($Segments | Where-Object {
            $sid = if ($_.PSObject.Properties['transport_zone_path'] -and $_.transport_zone_path) { ($_.transport_zone_path -split '/')[-1] } else { '(none)' }
            $sid -eq $id
        }).Count
        $srcName = if ($script:TzNames -and $script:TzNames.ContainsKey($id)) { $script:TzNames[$id] } else { $id }
        $match   = @($TargetTzs | Where-Object { $_.id -eq $id })
        $landing = if ($match.Count -gt 0) {
            $type = if ($match[0].PSObject.Properties['tz_type'] -and $match[0].tz_type) { $match[0].tz_type } else { 'UNKNOWN' }
            "lands in '$($match[0].display_name)' [$type] on the target"
        } elseif ($id -eq '(none)') {
            'no transport zone in the export'
        } else {
            'no zone with this id on the target'
        }
        $lines.Add(("{0} segment(s) from '{1}': {2}" -f $count, $srcName, $landing))
    }
    return @($lines)
}

function Select-TransportZone {
    # Fetches all transport zones from the target NSX and presents a numbered
    # selection menu. Returns a PSCustomObject with 'id', 'tz_type' and 'name',
    # or $null when the transport zone from the export is kept.
    # When the export comes from another NSX Manager (#17), Enter doesn't keep
    # the source zone silently: the menu shows where the segments would land
    # and asks for KEEP or a number; plain Enter shows the menu again.
    param([array]$Segments, [string]$SourceManager, [bool]$OtherManager)
    $tzPath = '/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones'
    try {
        $allTzs = @(Get-AllPages -Path $tzPath)
    } catch {
        Write-Warning "      Could not fetch transport zones: $_"
        if ($OtherManager) { throw "Could not read the transport zones of the target, and the export comes from another NSX Manager ($SourceManager). Run again with -TransportZoneId, or -KeepSourceTransportZone to keep the zone from the export." }
        return $null
    }

    if ($allTzs.Count -eq 0) {
        Write-Warning "      No transport zones found on target NSX"
        if ($OtherManager) { throw "No transport zones found on the target, and the export comes from another NSX Manager ($SourceManager). Run again with -TransportZoneId, or -KeepSourceTransportZone to keep the zone from the export." }
        return $null
    }

    $sorted = @($allTzs | Sort-Object display_name)
    $total  = $sorted.Count

    $showMenu = {
        Write-Host ""
        Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
        Write-Host "|  SELECT TARGET TRANSPORT ZONE                    |" -ForegroundColor Yellow
        Write-Host "|  Applied to all imported segments.               |" -ForegroundColor Yellow
        if ($OtherManager) {
        Write-Host "|  Export is from another NSX Manager: pick one.   |" -ForegroundColor Yellow
        } else {
        Write-Host "|  Press Enter to keep the TZ from the export.     |" -ForegroundColor Yellow
        }
        Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
        Write-Host ""
        for ($i = 0; $i -lt $total; $i++) {
            $tz   = $sorted[$i]
            $num  = ($i + 1).ToString().PadLeft($total.ToString().Length)
            $type = if ($tz.PSObject.Properties['tz_type'] -and $tz.tz_type) { $tz.tz_type } else { 'UNKNOWN' }
            Write-Host ("  [{0}] {1}  [{2}]" -f $num, $tz.display_name, $type)
        }
        Write-Host ""
    }
    & $showMenu

    $warned = $false
    while ($true) {
        $prompt = if ($OtherManager) { "  Select a number (or KEEP to keep the zone from the export)" } else { "  Select (or Enter to keep existing)" }
        $raw = Read-Answer $prompt

        if (-not $raw) {
            if (-not $OtherManager) {
                Write-Host "  Keeping transport zone from export" -ForegroundColor Gray
                Write-Host ""
                return $null
            }
            # Another manager: explain once, then show the menu again (#17)
            if (-not $warned) {
                Write-Host ""
                Write-Host "  The export comes from another NSX Manager ($SourceManager)." -ForegroundColor Yellow
                Write-Host "  Keeping the zone from the export means:" -ForegroundColor Yellow
                foreach ($l in (Get-SourceTzLanding -Segments $Segments -TargetTzs $sorted)) { Write-Host "    - $l" -ForegroundColor Yellow }
                Write-Host "  NSX's own default zones have the same id on every manager we tested, so a" -ForegroundColor Yellow
                Write-Host "  segment can land in the target's default zone, which VCF hosts don't use." -ForegroundColor Yellow
                Write-Host "  Pick the zone by number, or type KEEP if this is what you want." -ForegroundColor Yellow
                $warned = $true
            }
            & $showMenu
            continue
        }

        if ($OtherManager -and $raw -eq 'KEEP') {
            Write-Host "  Keeping transport zone from export (KEEP)" -ForegroundColor Yellow
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
                return [PSCustomObject]@{ id = $chosen.id; tz_type = $type; name = $chosen.display_name }
            }
        }

        $hint = if ($OtherManager) { "or type KEEP to keep the zone from the export" } else { "or press Enter to skip" }
        Write-Host "  Invalid selection - enter a number between 1 and $total, $hint" -ForegroundColor Red
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

# =============================================================================
#  SCRIPT METADATA
# =============================================================================

$ScriptMeta = @{
    Name    = "Import-NSXSegments.ps1"
    Version = "3.1"
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

# -- 1. Load export JSON ------------------------------------------------------
if ($KeepSourceTransportZone -and $TransportZoneId) { throw 'Use -TransportZoneId or -KeepSourceTransportZone, not both.' }

# No -InputPath / -NSXManager: ask for them (the exports found nearby, the
# managers with a saved credential)
if (-not $InputPath) {
    $InputPath = Select-ExportFile
    if (-not $InputPath) { Write-Host "  Nothing imported." -ForegroundColor Yellow; exit 0 }
}
if (-not $NSXManager) {
    $NSXManager = Read-NSXManager -Role 'TARGET NSX MANAGER (import into)'
    if (-not $NSXManager) { Write-Host "  Nothing imported." -ForegroundColor Yellow; exit 0 }
}
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
$ver = Test-NSXConnection
Write-Host "      NSX version : $($ver.product_version)" -ForegroundColor Green

# Determine transport zone id and type.
# The tz_type drives whether overlay validation is needed in the next step.
# Export from another NSX Manager (#17): keeping the source zone is then
# almost never right, so Enter at the menu doesn't do it silently.
$sourceManager = if ($exportData.PSObject.Properties['source_manager']) { "$($exportData.source_manager)" } else { '' }
$otherManager  = [bool]($sourceManager -and (Get-ManagerKey $sourceManager) -ne (Get-ManagerKey $NSXManager))
$script:TzUsedText = ''
if ($KeepSourceTransportZone) {
    $script:SelectedTzType = 'KEEP'
    $script:TzUsedText     = 'kept from the export (-KeepSourceTransportZone)'
    Write-Host "      -KeepSourceTransportZone: each segment keeps the transport zone from the export" -ForegroundColor Gray
    if ($otherManager) {
        Write-Host "      The export comes from another NSX Manager ($sourceManager):" -ForegroundColor Yellow
        try {
            $tzList = @(Get-AllPages -Path '/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones')
            foreach ($l in (Get-SourceTzLanding -Segments $selectedSegments -TargetTzs $tzList)) { Write-Host "        - $l" -ForegroundColor Yellow }
        } catch {
            Write-Warning "      Could not read the transport zones of the target: $_"
        }
    }
} elseif (-not $TransportZoneId) {
    # Interactive picker - returns { id, tz_type, name } or $null to keep source TZ
    $tzSelection = Select-TransportZone -Segments $selectedSegments -SourceManager $sourceManager -OtherManager $otherManager
    if ($tzSelection) {
        $TransportZoneId       = $tzSelection.id
        $script:SelectedTzType = $tzSelection.tz_type
        $script:TzUsedText     = "$($tzSelection.name) [$($tzSelection.tz_type)], chosen at the menu"
    } else {
        $script:TzUsedText     = if ($otherManager) { 'kept from the export (KEEP at the menu)' } else { 'kept from the export (Enter at the menu)' }
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
        $script:TzUsedText     = "$($tzObj.display_name) [$($script:SelectedTzType)], from -TransportZoneId"
    } catch {
        $script:TzUsedText     = "$TransportZoneId, from -TransportZoneId"
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
$declinedProfiles = 0
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
    } elseif ($WhatIfPreference) {
        Write-Host "      [WhatIf] Would PATCH profile '$($p.display_name)'"
        $wouldProfiles++
    } else {
        # No at -Confirm (#13): not a dry run, so not counted as "would"
        Write-Host "      [DECLINED] $($p.display_name) - not written" -ForegroundColor Yellow
        $declinedProfiles++
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
$declinedSegments = 0
$declinedBindings = 0
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
    # Listed only once the segment is written (or would be, in a dry run) (#13).
    $dcEntry = $null
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
        $dcEntry = [PSCustomObject]@{
            Segment = $s.display_name
            ConnectAtCutover = if ($srcGw) { $srcGw } else { '(none)' }
            Subnets = if ($subnetStr) { $subnetStr } else { '(none)' }
        }
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
            if ($dcEntry) { $disconnectedList.Add($dcEntry) }
        } catch {
            Write-Warning "      $counter [FAIL] $($s.display_name)$($was): $_"
            $errList.Add("Segment '$oldName': $_")
            $errSegments++
            continue   # skip binding maps - no point applying them if the segment failed
        }
    } elseif ($WhatIfPreference) {
        Write-Host "      $counter [WhatIf] Would PATCH segment '$($s.display_name)' at $apiPath"
        $wouldSegments++
        if ($dcEntry) { $disconnectedList.Add($dcEntry) }
    } else {
        # No at -Confirm (#13): the segment isn't there, so skip its binding maps
        Write-Host "      $counter [DECLINED] $($s.display_name) - not written, nor its binding maps" -ForegroundColor Yellow
        $declinedSegments++
        continue
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
            } elseif ($WhatIfPreference) {
                Write-Host "        [WhatIf] Would PATCH $bmApiPath"
                $wouldBindings++
            } else {
                Write-Host "        [DECLINED] $bmType/$bmId - not written" -ForegroundColor Yellow
                $declinedBindings++
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
    Write-Box -Title "DRY RUN (-WhatIf) into $($NSXManager): nothing was changed" -Color Cyan -Rows ([ordered]@{
        'Profiles that would be written' = $wouldProfiles
        'Segments that would be written' = $wouldSegments
        'Bindings that would be written' = $wouldBindings
        'Profiles already on target'     = $skipProfiles
        'Segments already on target'     = $skipSegments
        'Transport zone'                 = $script:TzUsedText
    })
} else {
    Write-Box -Title "IMPORT SUMMARY ($NSXManager)" -Color $statusColor -Rows ([ordered]@{
        'Profiles  OK / Failed' = "$okProfiles / $errProfiles"
        'Segments  OK / Failed' = "$okSegments / $errSegments"
        'Bindings  OK / Failed' = "$okBindings / $errBindings"
        'Skipped (on target)'   = "$skipProfiles profile(s) / $skipSegments segment(s)"
        'Transport zone'        = $script:TzUsedText
    })
    if ($declinedProfiles + $declinedSegments + $declinedBindings -gt 0) {
        Write-Host "  Declined at -Confirm, not written: $declinedProfiles profile(s), $declinedSegments segment(s), $declinedBindings binding map(s)" -ForegroundColor Yellow
    }
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
    # Closing line from the counts (#13): "successfully" only when everything
    # selected was written; otherwise say what was left as is and why.
    $written  = $okProfiles + $okSegments + $okBindings
    $leftAsIs = [System.Collections.Generic.List[string]]::new()
    if ($skipSegments + $skipProfiles -gt 0) {
        $leftAsIs.Add("$skipSegments segment(s) and $skipProfiles profile(s) already on the target, left as is (-UpdateExisting PATCHes them)")
    }
    if ($declinedProfiles + $declinedSegments + $declinedBindings -gt 0) {
        $leftAsIs.Add("$($declinedProfiles + $declinedSegments + $declinedBindings) object(s) declined at -Confirm")
    }
    if ($leftAsIs.Count -eq 0) {
        Write-Host "All items imported successfully!`n" -ForegroundColor Green
    } elseif ($written -eq 0) {
        Write-Host "Nothing imported: $($leftAsIs -join '; ').`n" -ForegroundColor Yellow
    } else {
        Write-Host "Imported $okSegments segment(s), $okProfiles profile(s) and $okBindings binding map(s); $($leftAsIs -join '; ').`n" -ForegroundColor Green
    }
}

# Exit codes (#10): 0 success (or dry run), 1 fatal error (thrown), 2 finished with errors
if ($totalErrors -gt 0) { exit 2 }
exit 0
