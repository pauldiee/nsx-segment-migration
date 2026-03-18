#Requires -Version 5.1
<#
.SYNOPSIS
    Imports NSX segments, custom segment profiles, and profile bindings from
    the JSON + CSV file pair produced by Export-NSXSegments.ps1.

.DESCRIPTION
    Reads the export JSON and the companion CSV name-mapping table, then
    PATCHes each object into the target NSX Manager via the Policy REST API.

    The CSV is auto-discovered by replacing the .json extension with .csv on
    the InputPath. Override this with -MappingPath if needed.

    CSV name-mapping rules
    ----------------------
    Rows where NewName = OldName (or NewName is blank) are treated as no-op.
    Segment rows        : renames the segment display_name and id.
    SegmentProfile rows : renames the profile; all binding paths are updated.
    T1Gateway rows      : remaps the connectivity_path T1 reference.

    Import order
    ------------
    1. Custom segment profiles  (must exist before segments reference them)
    2. Segments
    3. Profile binding maps     (applied per-segment after the segment is created)

    Transport zone selection
    ------------------------
    After connecting to the target NSX, an interactive menu lists all available
    transport zones so you can choose where the segments will land. Pressing
    Enter at the menu keeps the transport zone from the export file unchanged.
    Supply -TransportZoneId to skip the menu entirely (useful for automation).

    Overlay segment validation
    --------------------------
    If the selected transport zone is OVERLAY_BACKED, the script checks each
    segment for the two fields NSX requires for overlay segments:
      - connectivity_path  (T0 or T1 gateway connection)
      - subnets            (gateway IP and prefix, e.g. 192.168.10.1/24)
    If either is missing, the operator is prompted to supply the value
    interactively. Pressing Enter skips the field and the segment is imported
    without it (NSX may accept disconnected overlay segments in some topologies).
    VLAN-backed segments have no additional requirements and are imported as-is.

    NSX version compatibility
    -------------------------
    NSX 4.x stores profiles under  /infra/segment-profiles/<type>/
    NSX 9.x stores profiles under  /infra/<type>/
    Both formats are tried automatically when writing profiles. The path that
    succeeds is recorded and used for all subsequent binding map operations.

    Profile binding map types
    -------------------------
    segment-discovery-profile-binding-maps  (IP Discovery, MAC Discovery)
    segment-security-profile-binding-maps   (Segment Security, SpoofGuard)
    segment-qos-profile-binding-maps        (QoS)

.PARAMETER NSXManager
    FQDN or IP address of the target NSX Manager.

.PARAMETER Credential
    PSCredential for the NSX Manager admin account. Prompted if omitted.

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

.PARAMETER SkipCertCheck
    Bypass TLS certificate validation. Use for self-signed certificates.

.EXAMPLE
    # Standard import - CSV auto-discovered next to the JSON
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -InputPath ./nsx-export_20260101_120000.json -SkipCertCheck

.EXAMPLE
    # Override transport zone, supply the CSV explicitly
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -InputPath ./exports/prod-migration.json `
        -MappingPath ./exports/prod-migration.csv `
        -TransportZoneId tz-overlay-prod `
        -SkipCertCheck

.EXAMPLE
    # Dry run - preview all changes without touching NSX
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -InputPath ./nsx-export_20260101_120000.json -WhatIf

.EXAMPLE
    # Use a saved credential so you are not prompted each run
    $cred = Import-Clixml "$env:USERPROFILE\nsx-cred.xml"
    .\Import-NSXSegments.ps1 -NSXManager nsx9.corp.local `
        -Credential $cred `
        -InputPath ./nsx-export_20260101_120000.json -SkipCertCheck

.NOTES
    Version : 2.1
    API     : NSX Policy REST API v1 (compatible with NSX 4.x and 9.x)
    Pair    : Export-NSXSegments.ps1
    Author  : Paul van Dieen
    Blog    : https://www.hollebollevsan.nl
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
            Write-Host "      [RENAME] $type '$oldName' -> '$newName'"
            $changes++
        } else {
            $kept++
        }
    }

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
        Write-Host "      [RENAME] $Type '$oldName' -> '$newName'"
    }
    return $Obj
}

function Select-Segments {
    # Presents a numbered, sorted segment list and returns the operator's selection.
    # Input formats accepted: individual numbers, comma-separated, ranges (1-5),
    # mixed (1,3,7-10), or * for all.
    param([array]$Segments)

    $sorted = @($Segments | Sort-Object display_name)
    $total  = $sorted.Count

    Write-Host ""
    Write-Host "+--------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "|  SELECT SEGMENTS TO IMPORT                       |" -ForegroundColor Yellow
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
        $raw = (Read-Host "  Select (or Enter to keep existing)").Trim()

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
                    $raw = (Read-Host "  Gateway for '$segName'").Trim()
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
                $raw = (Read-Host "  Subnet for '$segName'").Trim()
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
#  MAIN
# =============================================================================

Write-Host @"
+==================================================+
|   Import-NSXSegments.ps1  v2.1                   |
|   Compatible with NSX 4.x and 9.x                |
+==================================================+
"@ -ForegroundColor Cyan

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

# Interactive segment selection
$selectedSegments = @(Select-Segments -Segments @($exportData.segments))
if ($selectedSegments.Count -eq 0) {
    Write-Warning "No segments selected. Nothing to import."
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
if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter credentials for NSX Manager ($NSXManager)"
}
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
if ($script:SelectedTzType -eq 'OVERLAY_BACKED') {
    Write-Host "`n      Checking overlay segment requirements ..." -ForegroundColor Cyan
    $selectedSegments = @(Confirm-OverlaySegmentConfig -Segments $selectedSegments)
}

# -- 4. Import segment profiles -----------------------------------------------
Write-Host "`n[4/5] Importing custom segment profiles ..." -ForegroundColor Cyan

$okProfiles  = 0
$errProfiles = 0
$errList     = @()

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
    $p             = Remove-ReadOnlyFields -Obj $p
    $body          = $p | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess($NSXManager, "PATCH profile '$($p.display_name)'")) {
        $written = $false
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
                Write-Verbose "      $tryPath failed, trying next..."
            }
        }
        if (-not $written) {
            Write-Warning "      [FAIL] $($p.display_name) - could not be written to any API path"
            $errList += "Profile '$($profile.display_name)': all API paths failed"
            $errProfiles++
        }
    } else {
        Write-Host "      [WhatIf] Would PATCH profile '$($p.display_name)'"
    }
}

# -- 5. Import segments and profile binding maps ------------------------------
Write-Host "`n[5/5] Importing segments ..." -ForegroundColor Cyan

$okSegments  = 0
$errSegments = 0

foreach ($segment in $selectedSegments) {

    # Deep-clone so we never mutate the in-memory export data
    $s       = $segment | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $oldName = $s.display_name
    $oldId   = $s.id   # preserve the original id for binding map lookup after rename

    $s = Resolve-Name -Obj $s -Type 'Segment' -Map $nameMap

    # Remap T1 gateway reference if the CSV maps this gateway to a different id
    # on the target NSX (T0 gateways use a different path prefix - not remapped here)
    if ($s.PSObject.Properties['connectivity_path'] -and $s.connectivity_path -and
        $s.connectivity_path -match '/tier-1s/([^/]+)') {
        $oldT1 = $Matches[1]
        if ($nameMap['T1Gateway'].ContainsKey($oldT1)) {
            $newT1               = $nameMap['T1Gateway'][$oldT1]
            $s.connectivity_path = $s.connectivity_path -replace [regex]::Escape($oldT1), $newT1
            Write-Host "      [REMAP T1] '$oldT1' -> '$newT1'"
        }
    }

    # Apply transport zone override if one was selected or supplied
    if ($TransportZoneId) {
        $s.transport_zone_path = "/infra/sites/default/enforcement-points/default/transport-zones/$TransportZoneId"
        Write-Host "      [TZ] $TransportZoneId applied to '$($s.display_name)'"
    }

    $s       = Remove-ReadOnlyFields -Obj $s
    $segId   = $s.id
    $apiPath = "/policy/api/v1/infra/segments/$segId"
    $body    = $s | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess($NSXManager, "PATCH segment '$($s.display_name)'")) {
        try {
            $null = Invoke-NSXApi -Path $apiPath -Method PATCH -Body $body
            Write-Host "      [OK] $($s.display_name)" -ForegroundColor Green
            $okSegments++
        } catch {
            Write-Warning "      [FAIL] $($s.display_name): $_"
            $errList += "Segment '$oldName': $_"
            $errSegments++
            continue   # skip binding maps - no point applying them if the segment failed
        }

        # Apply profile binding maps for this segment.
        # The export keys binding maps by the original segment id (before any rename)
        # so we look up by $oldId first, then fall back to $segId (the post-rename id)
        # for exports produced before renaming was introduced.
        $entryKey = if ($exportBindingMaps.ContainsKey($oldId))   { $oldId  }
                    elseif ($exportBindingMaps.ContainsKey($segId)) { $segId  }
                    else                                             { $null  }

        if ($entryKey) {
            $entries = @($exportBindingMaps[$entryKey])
            Write-Host "      Applying $($entries.Count) profile binding(s)"

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
                        Write-Host "        [REMAP] $($prop.Name): $($prop.Value) -> $newVal"
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
                    } catch {
                        Write-Warning "        [FAIL] $bmType/$bmId : $_"
                        $errList += "$bmType '$bmOldId' on segment '$oldName': $_"
                    }
                } else {
                    Write-Host "        [WhatIf] Would PATCH $bmApiPath"
                }
            }
        } else {
            Write-Host "      No profile bindings in export for '$oldName'"
        }

    } else {
        Write-Host "      [WhatIf] Would PATCH segment '$($s.display_name)' at $apiPath"
    }
}

# -- Summary ------------------------------------------------------------------
$totalErrors = $errProfiles + $errSegments
$statusColor = if ($totalErrors -eq 0) { 'Green' } else { 'Yellow' }

Write-Host @"

+==================================================+
|   IMPORT SUMMARY                                 |
+==================================================+
|  Profiles  OK / Failed : $("$okProfiles / $errProfiles".PadRight(24))|
|  Segments  OK / Failed : $("$okSegments / $errSegments".PadRight(24))|
+==================================================+
"@ -ForegroundColor $statusColor

if ($errList.Count -gt 0) {
    Write-Host "`nErrors:" -ForegroundColor Red
    $errList | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} else {
    Write-Host "All items imported successfully!`n" -ForegroundColor Green
}
