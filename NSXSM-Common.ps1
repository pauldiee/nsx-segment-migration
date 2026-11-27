#Requires -Version 5.1

<#
.SYNOPSIS
    Shared helpers for Export-NSXSegments.ps1, Import-NSXSegments.ps1 and
    Remove-NSXSegments.ps1: REST calls, pickers, prompts and credentials.

.DESCRIPTION
    Not a script to run on its own. Each of the three scripts dot-sources
    this file from its own folder and stops with a clear message when it is
    missing, so keep the scripts and NSXSM-Common.ps1 together.

    What lives here:
      - REST: Get-BasicAuthHeader, Set-TlsSkipCert, Invoke-NSXApi (with an
        optional -Body), Get-NSXErrorText, Get-AllPages
      - Picker: Select-FromList with Write-PickerList, Test-CancelInput,
        Get-SegmentLine and Get-TransportZoneNames, and the picker settings
        ($PickerListMax, $script:PickerCancelled, $script:TzNames)
      - Prompts and credentials: Read-Answer, Resolve-Credential,
        Read-NSXCredential, Get-/Save-/Remove-SavedCredential and the
        credential paths (<manager>.cred next to the scripts)

    The functions read the calling script's $NSXManager, $SkipCertCheck and
    $script:Headers, exactly as they did when each script carried its own
    copy.

.NOTES
    Script   : NSXSM-Common.ps1
    Version  : 1.3.0
    Author   : Paul van Dieen
    Blog     : https://www.hollebollevsan.nl
    Requires : PowerShell 5.1 or later; dot-sourced by Export-, Import- and Remove-NSXSegments.ps1 from the same folder
    Tested   : Lab, 2026-11-27: NSX 4.2.4.1 (home lab) and NSX 9.0.2 (Holodeck lab B),
               PowerShell 7 and 5.1; NSX 9.1.1 (Holodeck lab A) up to 2026-11-16.
               See tests/TESTPLAN.md
    GitHub   : https://github.com/pauldiee/nsx-segment-migration
#>

<# CHANGELOG
    v1.3.0  2026-11-27  Paul van Dieen
        - Versions as x.y.z ($NSXSMCommonVersion 1.3.0) and this changelog
          in its own block (#24).
        - Every "no console input" stop starts with "No console input" (the
          password prompt too), so the scripts can exit with 2 for it, as
          the vCenter toolkits do (#24).
        - Picker line: a VLAN segment without a gateway also says "no
          gateway", so /no gateway picks every segment without one (#24).

    v1.2.0  2026-11-27  Paul van Dieen
        - Interactive start and layout: Read-NSXManager (saved managers as
          numbers, or a name), Select-ExportFile (exports in the current and
          script folder with source, date and counts), Test-NSXConnection
          (offers to go on without the certificate check when it is not
          trusted), Write-Box (summary boxes that fit their content),
          Test-InteractiveInput. Credentials are saved as <manager>.cred
          next to the scripts, as in the vCenter toolkits; creds\ (1.0/1.1)
          and the user profile are still read. Without a console, the
          password prompt stops with a message instead of waiting forever.

    v1.1.0  2026-11-27  Paul van Dieen
        - Invoke-NSXApi: a call that gets no HTTP answer (untrusted
          certificate, DNS, refused connection) showed "The property
          'Response' cannot be found on this object" instead of the real
          error, because StrictMode stops on the missing property (#18). The
          real error is shown now, with a hint to -SkipCertCheck when the
          certificate is not trusted.

    v1.0.0  2026-11-27  Paul van Dieen
        - The helpers that Export 2.4, Import 2.7 and Remove 1.5 each
          carried as their own copy, moved here unchanged (#11). Taken from
          Import 2.7; the copies differed only in comments and in
          Invoke-NSXApi's -Body parameter, which Export and Remove don't
          pass.
#>

Set-StrictMode -Version Latest

# Read by the scripts: they stop when this file is older than they need,
# and show it in their banner.
$NSXSMCommonVersion = '1.3.0'

# =============================================================================
#  REST
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
        # A failure without an HTTP answer (TLS, DNS, refused connection) has
        # no Response property; under StrictMode reading it hid the real
        # error behind "The property 'Response' cannot be found" (#18).
        $resp = if ($_.Exception.PSObject.Properties['Response']) { $_.Exception.Response } else { $null }
        $code = if ($resp -and $resp.PSObject.Properties['StatusCode'] -and $resp.StatusCode) {
            [int]$resp.StatusCode
        } else { 'N/A' }
        $msg = Get-NSXErrorText -ErrorRecord $_
        if ($code -eq 'N/A') {
            $all = "$msg $($_.Exception.InnerException)"
            if ($all -match 'SSL|certificate|trust relationship|RemoteCertificate') {
                $msg += ' -- the certificate of the NSX Manager is not trusted: pass -SkipCertCheck for a self-signed certificate, or import the CA root.'
            }
        }
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

# =============================================================================
#  PICKER
# =============================================================================

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
    else { $tags.Add('no gateway') }   # VLAN too, so /no gateway picks them all (#24)
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

# =============================================================================
#  PROMPTS AND CREDENTIALS
# =============================================================================

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
    # <manager>.cred next to the scripts, as in the vCenter toolkits
    # (VIRoleManager, VITagManager, ...). Up to Common 1.1 it was creds\.
    param([string]$Manager)
    $safe = $Manager -replace '[^a-zA-Z0-9.\-]', '_'
    return Join-Path $PSScriptRoot "$safe.cred"
}

function Get-OldCredentialPath {
    # Where Common 1.0/1.1 (and the scripts from #3) saved it: creds\.
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
    # Loads a saved credential for the given NSX Manager: <manager>.cred
    # next to the scripts, else the older places (creds\, then the user
    # profile). Returns the PSCredential, or $null if there is none.
    param([string]$Manager)
    $current = Get-CredentialPath -Manager $Manager
    foreach ($path in $current, (Get-OldCredentialPath -Manager $Manager), (Get-LegacyCredentialPath -Manager $Manager)) {
        if (Test-Path -LiteralPath $path) {
            try {
                $cred = Import-Clixml -Path $path
                if ($path -ne $current) {
                    Write-Host "      Using the old credential file $path; choose [2] to save it next to the scripts." -ForegroundColor Gray
                }
                return $cred
            } catch { }
        }
    }
    return $null
}

function Save-Credential {
    # Saves a credential to <manager>.cred next to the scripts. On
    # Windows Export-Clixml encrypts the password with DPAPI (only this user
    # on this machine can read it); on Linux and macOS it is NOT encrypted.
    param([System.Management.Automation.PSCredential]$Cred, [string]$Manager)
    $path = Get-CredentialPath -Manager $Manager
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
    foreach ($path in (Get-CredentialPath -Manager $Manager), (Get-OldCredentialPath -Manager $Manager), (Get-LegacyCredentialPath -Manager $Manager)) {
        if (Test-Path -LiteralPath $path) {
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
    # Read-Host -AsSecureString reads the console, not a redirected stdin:
    # without a console it would wait forever (1.2)
    if (-not (Test-InteractiveInput)) { throw "No console input for the NSX password: it can only be typed in an interactive PowerShell window. Run the script there once and save the credential, or pass -Credential." }
    $pass = Read-Host "  NSX password" -AsSecureString
    if ($null -eq $pass) { throw "No console input for the NSX password. Run the script interactively or pass -Credential." }
    return [System.Management.Automation.PSCredential]::new($user, $pass)
}

# =============================================================================
#  INTERACTIVE START AND LAYOUT (1.2)
# =============================================================================

function Test-InteractiveInput {
    # True when a person can answer a prompt (not a redirected stdin, a
    # pipeline or a scheduled task). Optional prompts are only asked then.
    try { return (-not [Console]::IsInputRedirected) } catch { return $false }
}

function Read-NSXManager {
    # Asks for the NSX Manager when -NSXManager is not given: the managers
    # with a saved credential (*.cred next to the scripts, and the older
    # creds\ folder; file names only) as numbers, or a name typed in.
    # Returns the name, or $null on cancel.
    param([string]$Role = 'NSX Manager')
    $saved = @(@($PSScriptRoot, (Join-Path $PSScriptRoot 'creds')) |
        Where-Object { Test-Path -LiteralPath $_ } |
        ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter '*.cred' -File } |
        Sort-Object LastWriteTime -Descending | ForEach-Object { $_.BaseName } | Select-Object -Unique)
    Write-Host ''
    Write-Host "  $Role" -ForegroundColor Yellow
    if ($saved.Count -gt 0) {
        Write-Host '  Saved credential for:' -ForegroundColor DarkGray
        Write-PickerList -Lines $saved -Full
        Write-Host "  Type a number, or the FQDN or IP of another NSX Manager; 'cancel' stops." -ForegroundColor DarkGray
    } else {
        Write-Host "  Type the FQDN or IP of the NSX Manager; 'cancel' stops." -ForegroundColor DarkGray
    }
    Write-Host ''
    while ($true) {
        $raw = Read-Answer '  NSX Manager'
        if (-not $raw) { continue }
        if (Test-CancelInput -Text $raw) { return $null }
        if ($raw -match '^\d+$' -and $saved.Count -gt 0) {
            $n = [int]$raw
            if ($n -ge 1 -and $n -le $saved.Count) { Write-Host "  Using $($saved[$n - 1])" -ForegroundColor Green; return $saved[$n - 1] }
            Write-Host "  Enter a number between 1 and $($saved.Count), or a name" -ForegroundColor Red
            continue
        }
        $name = ($raw -replace '^https?://', '' -replace '/+$', '')
        if ($name -match '\s') { Write-Host '  A name or IP has no spaces' -ForegroundColor Red; continue }
        return $name
    }
}

function Select-ExportFile {
    # Asks for the export when Import runs without -InputPath: the exports
    # (JSON from Export-NSXSegments.ps1) in the current folder and the
    # script folder, newest first, with their source, date and counts; or a
    # path typed in. Returns the full path, or $null on cancel.
    $dirs  = @((Get-Location).Path, $PSScriptRoot) | Select-Object -Unique
    $files = @($dirs | ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter '*.json' -File -ErrorAction SilentlyContinue } |
        Sort-Object LastWriteTime -Descending | Group-Object FullName | ForEach-Object { $_.Group[0] })
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $files) {
        if ($items.Count -ge 20) { break }
        try { $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { continue }
        if (-not ($j.PSObject.Properties['segments'] -and $j.PSObject.Properties['source_manager'])) { continue }
        $prof = if ($j.PSObject.Properties['segment_profiles']) { @($j.segment_profiles).Count } else { 0 }
        $line = '{0}  [from {1}, {2} segment(s), {3} profile(s), {4:dd-MM-yyyy HH:mm}]' -f $f.Name, $j.source_manager, @($j.segments).Count, $prof, $f.LastWriteTime
        $items.Add([pscustomobject]@{ Path = $f.FullName; Line = $line })
    }
    Write-Host ''
    Write-Host '  EXPORT TO IMPORT' -ForegroundColor Yellow
    if ($items.Count -gt 0) {
        Write-Host "  Exports in $($dirs -join ' and '):" -ForegroundColor DarkGray
        Write-PickerList -Lines @($items | ForEach-Object { $_.Line }) -Full
        Write-Host "  Type a number, or the path of an export .json; 'cancel' stops." -ForegroundColor DarkGray
    } else {
        Write-Host "  No exports from Export-NSXSegments.ps1 in $($dirs -join ' or ')." -ForegroundColor DarkGray
        Write-Host "  Type the path of an export .json; 'cancel' stops." -ForegroundColor DarkGray
    }
    Write-Host ''
    while ($true) {
        $raw = Read-Answer '  Export'
        if (-not $raw) { continue }
        if (Test-CancelInput -Text $raw) { return $null }
        if ($raw -match '^\d+$' -and $items.Count -gt 0) {
            $n = [int]$raw
            if ($n -ge 1 -and $n -le $items.Count) { return $items[$n - 1].Path }
            Write-Host "  Enter a number between 1 and $($items.Count), or a path" -ForegroundColor Red
            continue
        }
        $path = $raw.Trim('"', "'")
        if (Test-Path -LiteralPath $path -PathType Leaf) { return (Resolve-Path -LiteralPath $path).Path }
        Write-Host "  File not found: $path" -ForegroundColor Red
    }
}

function Test-NSXConnection {
    # Reads the NSX version. When the certificate is not trusted and
    # -SkipCertCheck was not given, asks whether to go on without checking
    # it for this run; without an answer (or No) it throws the real error.
    try {
        return (Invoke-NSXApi -Path '/api/v1/node/version')
    } catch {
        $err = "$_"
        if (-not $SkipCertCheck -and $err -match 'not trusted') {
            Write-Host "      The certificate of $NSXManager is not trusted (self-signed, or its CA is not imported on this machine)." -ForegroundColor Yellow
            # No one to answer (scheduled task, closed stdin): the real error, not "no console input"
            $a = try { Read-Answer '      Continue without checking the certificate for this run? (y/N)' } catch { '' }
            if ($a -match '^(y|yes|j|ja)$') {
                $script:SkipCertCheck = [switch]$true
                if ($PSVersionTable.PSVersion.Major -lt 6) { Set-TlsSkipCert }
                Write-Host '      Certificate check off for this run. Next time add -SkipCertCheck.' -ForegroundColor Gray
                return (Invoke-NSXApi -Path '/api/v1/node/version')
            }
        }
        throw
    }
}

function Format-BoxValue {
    # Shortens a value to $Max characters, keeping the end (a file name).
    param([string]$Text, [int]$Max)
    if ($Text.Length -le $Max) { return $Text }
    if ($Max -le 3) { return $Text.Substring(0, $Max) }
    return '...' + $Text.Substring($Text.Length - ($Max - 3))
}

function Write-Box {
    # A summary box that fits its content: title, then one row per
    # label/value pair (an ordered dictionary). The box grows with the
    # longest value up to the console width; longer values keep their end.
    param([string]$Title, [System.Collections.IDictionary]$Rows, [string]$Color = 'Green', [int]$MinWidth = 50)
    $labelW = 0; $valueW = 0
    foreach ($k in $Rows.Keys) {
        if ("$k".Length -gt $labelW) { $labelW = "$k".Length }
        if ("$($Rows[$k])".Length -gt $valueW) { $valueW = "$($Rows[$k])".Length }
    }
    $maxInner = 116
    try { if ([Console]::WindowWidth -gt 20) { $maxInner = [Console]::WindowWidth - 3 } } catch { }
    $inner  = [Math]::Max($MinWidth, [Math]::Max($Title.Length + 6, $labelW + $valueW + 7))
    $inner  = [Math]::Min($inner, [Math]::Max($MinWidth, $maxInner))
    $valMax = [Math]::Max(5, $inner - $labelW - 7)
    $edge   = '+' + ('=' * $inner) + '+'
    $lines  = [System.Collections.Generic.List[string]]::new()
    $lines.Add(''); $lines.Add($edge)
    $lines.Add('|   ' + $Title.PadRight($inner - 3) + '|')
    $lines.Add($edge)
    foreach ($k in $Rows.Keys) {
        $v = Format-BoxValue -Text "$($Rows[$k])" -Max $valMax
        $lines.Add('|  ' + ("$k".PadRight($labelW) + ' : ' + $v).PadRight($inner - 3) + ' |')
    }
    $lines.Add($edge)
    foreach ($l in $lines) { Write-Host $l -ForegroundColor $Color }
}