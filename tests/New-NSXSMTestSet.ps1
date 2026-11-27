#Requires -Version 7.0

<#
.SYNOPSIS
    Builds, shows or removes a throwaway test set in a LAB NSX Manager for
    Export-, Import- and Remove-NSXSegments.ps1.

.DESCRIPTION
    Lab use only. Every object it creates is named NSXSM-T-*, and Remove only
    deletes NSXSM-T-* objects (also copies an import made under that prefix).

    Create builds:
        Profiles (custom, one of each type the export carries):
          NSXSM-T-QoS, NSXSM-T-SpoofGuard, NSXSM-T-IPDisc, NSXSM-T-MACDisc,
          NSXSM-T-SegSec
        Tier-1:
          NSXSM-T-T1        no NSX Edge cluster (distributed only),
                            advertises its connected segments
        Segments:
          NSXSM-T-Ovl-GW1   overlay, connected to NSXSM-T-T1, 10.99.1.1/24,
                            all five custom profiles bound
          NSXSM-T-Ovl-GW2   overlay, connected to NSXSM-T-T1, 10.99.2.1/24,
                            default profiles
          NSXSM-T-Ovl-NoGW  overlay, Connectivity None, no subnet
          NSXSM-T-VLAN199   VLAN segment, VLAN 199

    Show lists every NSXSM-T-* segment with its transport zone type,
    gateway connection, subnets, VLAN and bound custom profiles, so an
    import can be compared with the source. Remove deletes the bindings,
    the segments, the Tier-1 and the profiles, in that order.

    Profiles are written to /infra/<type>/ and, if the manager answers 404
    there, to /infra/segment-profiles/<type>/, the same two paths the
    export reads.

.PARAMETER NSXManager
    FQDN or IP of the LAB NSX Manager.

.PARAMETER Mode
    Create, Show or Remove.

.PARAMETER Credential
    NSX admin credential. Defaults to the file the toolkit saves:
    %USERPROFILE%\.nsx_cred_<manager>.xml (DPAPI, Windows only).

.PARAMETER SkipCertCheck
    Accept a self-signed lab certificate.

.EXAMPLE
    .\tests\New-NSXSMTestSet.ps1 -NSXManager 192.168.2.66 -Mode Create -SkipCertCheck

.NOTES
    Script   : New-NSXSMTestSet.ps1
    Version  : 1.0.2
    Author   : Paul van Dieen
    Blog     : https://www.hollebollevsan.nl
    Requires : PowerShell 7+, NSX Manager admin (Policy API)
    Tested   : NSX 4.2.4.1 (lab), 2026-11-16
#>

<# CHANGELOG
v1.0.2  2026-11-27  Paul van Dieen
- Reads the credential from <manager>.cred next to the toolkit scripts
  (NSXSM-Common 1.2, #20) first, then creds\ and the user profile.

    v1.0.1  2026-11-18  Paul van Dieen
        - Get-Help shows the full help again: the changelog moved out of the
          help block into its own comment block (the unknown .CHANGELOG
          keyword made Get-Help ignore the whole help block)
        - Blank line between #Requires and the help block, for the same reason

    v1.0.0  2026-11-16  Paul van Dieen
        - Initial release: Create / Show / Remove of the segment test set
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][ValidateSet('Create', 'Show', 'Remove')][string]$Mode,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SkipCertCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptVersion = '1.0.2'
$scriptAuthor  = 'Paul van Dieen'
$scriptBlogUrl = 'https://www.hollebollevsan.nl'
$prefix        = 'NSXSM-T-'

Write-Host ('=' * 62) -ForegroundColor DarkCyan
Write-Host ('  New-NSXSMTestSet.ps1' + (' ' * 25) + "v$scriptVersion") -ForegroundColor Cyan
Write-Host "  $scriptAuthor - $scriptBlogUrl" -ForegroundColor Gray
Write-Host '  LAB USE ONLY - touches NSXSM-T-* objects only' -ForegroundColor Yellow
Write-Host ('=' * 62) -ForegroundColor DarkCyan

if (-not $Credential) {
    # Same files as the toolkit: <manager>.cred in the repo root (Common 1.2), creds\<manager>.cred, or the
    # pre-#3 file in the user profile.
    $candidates = @(
        (Join-Path (Split-Path $PSScriptRoot -Parent) "$($NSXManager -replace '[^a-zA-Z0-9.\-]', '_').cred"),
        (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'creds') "$($NSXManager -replace '[^a-zA-Z0-9.\-]', '_').cred"),
        (Join-Path $(if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }) ".nsx_cred_$($NSXManager -replace '[^a-zA-Z0-9]','_').xml")
    )
    $credPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $credPath) { throw "No credential file found ($($candidates -join ' or ')). Pass -Credential or save one with the toolkit first." }
    $Credential = Import-Clixml -Path $credPath
}
$pair    = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
$headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair)) }

function Invoke-Nsx {
    param([string]$Path, [string]$Method = 'GET', $Body)
    $p = @{ Uri = "https://$NSXManager/policy/api/v1$Path"; Method = $Method; Headers = $headers
            ContentType = 'application/json'; SkipCertificateCheck = [bool]$SkipCertCheck }
    if ($null -ne $Body) { $p['Body'] = ($Body | ConvertTo-Json -Depth 10) }
    Invoke-RestMethod @p
}

function Get-All {
    param([string]$Path)
    $out = @(); $cursor = $null
    do {
        $sep  = if ($Path -match '\?') { '&' } else { '?' }
        $page = if ($cursor) { Invoke-Nsx "$Path${sep}cursor=$cursor" } else { Invoke-Nsx $Path }
        if ($page.PSObject.Properties['results'] -and $page.results) { $out += $page.results }
        $cursor = if ($page.PSObject.Properties['cursor']) { $page.cursor } else { $null }
    } while ($cursor)
    if ($out.Count) { $out }   # emit items one by one; nothing at all when empty
}

function Get-StatusCode { param($Err) try { [int]$Err.Exception.Response.StatusCode } catch { 0 } }

# Profile types: name suffix -> API type folder, plus the body to create it with.
$profiles = [ordered]@{
    'QoS'        = @{ Type = 'qos-profiles';              Body = @{ class_of_service = 3 } }
    'SpoofGuard' = @{ Type = 'spoofguard-profiles';       Body = @{} }
    'IPDisc'     = @{ Type = 'ip-discovery-profiles';     Body = @{} }
    'MACDisc'    = @{ Type = 'mac-discovery-profiles';    Body = @{ mac_learning_enabled = $true } }
    'SegSec'     = @{ Type = 'segment-security-profiles'; Body = @{} }
}

function Set-Profile {
    # PATCH under /infra/<type>/ and fall back to /infra/segment-profiles/<type>/ on 404.
    param([string]$Name, [string]$Type, [hashtable]$Body)
    $b = @{ display_name = $Name; description = 'nsx-segment-migration test set' } + $Body
    foreach ($base in "/infra/$Type", "/infra/segment-profiles/$Type") {
        try {
            $null = Invoke-Nsx -Path "$base/$Name" -Method PATCH -Body $b
            return (Invoke-Nsx "$base/$Name").path
        } catch {
            if ((Get-StatusCode $_) -ne 404) { throw }
        }
    }
    throw "Could not create $Type/$Name under either path."
}

function Get-TestProfiles {
    $found = @()
    foreach ($t in $profiles.Values.Type) {
        foreach ($base in "/infra/$t", "/infra/segment-profiles/$t") {
            try { $found += @(Get-All $base | Where-Object { $_.display_name -like "$prefix*" }) } catch { if ((Get-StatusCode $_) -ne 404) { throw } }
        }
    }
    $found | Sort-Object path -Unique
}

$bindingTypes = 'segment-qos-profile-binding-maps', 'segment-discovery-profile-binding-maps', 'segment-security-profile-binding-maps'

$version = (Invoke-RestMethod -Uri "https://$NSXManager/api/v1/node/version" -Headers $headers -SkipCertificateCheck:$SkipCertCheck).product_version
Write-Host "  Connected to $NSXManager (NSX $version)" -ForegroundColor Green

switch ($Mode) {
    'Create' {
        $tzs = Get-All '/infra/sites/default/enforcement-points/default/transport-zones'
        $ovl  = $tzs | Where-Object { $_.tz_type -like 'OVERLAY*' } | Sort-Object { -not $_.is_default } | Select-Object -First 1
        $vlan = $tzs | Where-Object { $_.tz_type -like 'VLAN*' }    | Sort-Object { -not $_.is_default } | Select-Object -First 1
        if (-not $ovl -or -not $vlan) { throw 'Need an overlay and a VLAN transport zone on this NSX Manager.' }
        Write-Host "  Transport zones: overlay '$($ovl.display_name)', VLAN '$($vlan.display_name)'"

        $pp = @{}
        foreach ($k in $profiles.Keys) {
            $pp[$k] = Set-Profile -Name "$prefix$k" -Type $profiles[$k].Type -Body $profiles[$k].Body
            Write-Host "  Profile $prefix$k -> $($pp[$k])"
        }

        $t1 = "${prefix}T1"
        $null = Invoke-Nsx -Path "/infra/tier-1s/$t1" -Method PATCH -Body @{
            display_name = $t1; description = 'nsx-segment-migration test set'; route_advertisement_types = @('TIER1_CONNECTED') }
        Write-Host "  Tier-1 $t1 (no Edge cluster)"

        $segs = [ordered]@{
            "${prefix}Ovl-GW1"  = @{ transport_zone_path = $ovl.path; connectivity_path = "/infra/tier-1s/$t1"; subnets = @(@{ gateway_address = '10.99.1.1/24' }) }
            "${prefix}Ovl-GW2"  = @{ transport_zone_path = $ovl.path; connectivity_path = "/infra/tier-1s/$t1"; subnets = @(@{ gateway_address = '10.99.2.1/24' }) }
            "${prefix}Ovl-NoGW" = @{ transport_zone_path = $ovl.path }
            "${prefix}VLAN199"  = @{ transport_zone_path = $vlan.path; vlan_ids = @('199') }
        }
        foreach ($s in $segs.Keys) {
            $null = Invoke-Nsx -Path "/infra/segments/$s" -Method PATCH -Body (@{ display_name = $s; description = 'nsx-segment-migration test set' } + $segs[$s])
            Write-Host "  Segment $s"
        }

        $g1 = "/infra/segments/${prefix}Ovl-GW1"
        $null = Invoke-Nsx -Path "$g1/segment-qos-profile-binding-maps/${prefix}qos" -Method PATCH -Body @{ qos_profile_path = $pp['QoS'] }
        $null = Invoke-Nsx -Path "$g1/segment-discovery-profile-binding-maps/${prefix}disc" -Method PATCH -Body @{
            ip_discovery_profile_path = $pp['IPDisc']; mac_discovery_profile_path = $pp['MACDisc'] }
        $null = Invoke-Nsx -Path "$g1/segment-security-profile-binding-maps/${prefix}sec" -Method PATCH -Body @{
            segment_security_profile_path = $pp['SegSec']; spoofguard_profile_path = $pp['SpoofGuard'] }
        Write-Host "  Bound all five custom profiles to ${prefix}Ovl-GW1" -ForegroundColor Green
        Write-Host '  Done. Run -Mode Show to list the set.' -ForegroundColor Green
    }

    'Show' {
        $tzs  = Get-All '/infra/sites/default/enforcement-points/default/transport-zones'
        $segs = Get-All '/infra/segments' | Where-Object { $_.display_name -like "$prefix*" } | Sort-Object display_name
        $rows = foreach ($s in $segs) {
            $tz = $tzs | Where-Object { $_.path -eq $s.transport_zone_path } | Select-Object -First 1
            $bound = foreach ($bt in $bindingTypes) {
                foreach ($m in (Get-All "/infra/segments/$($s.id)/$bt")) {
                    $m.PSObject.Properties | Where-Object { $_.Name -like '*_profile_path' -and $_.Value -match "/$prefix" } |
                        ForEach-Object { ($_.Value -split '/')[-1] }
                }
            }
            [pscustomobject]@{
                Segment  = $s.display_name
                TZ       = if ($tz) { $tz.tz_type } else { $s.transport_zone_path }
                Gateway  = if ($s.PSObject.Properties['connectivity_path'] -and $s.connectivity_path) { ($s.connectivity_path -split '/')[-1] } else { 'None' }
                Subnets  = if ($s.PSObject.Properties['subnets'] -and $s.subnets) { ($s.subnets.gateway_address -join ',') } else { '' }
                VLAN     = if ($s.PSObject.Properties['vlan_ids'] -and $s.vlan_ids) { $s.vlan_ids -join ',' } else { '' }
                Profiles = (@($bound) | Sort-Object) -join ','
            }
        }
        if ($rows) { $rows | Format-Table -AutoSize | Out-String -Width 220 | Write-Host } else { Write-Host '  No NSXSM-T-* segments.' }
        $t1s = Get-All '/infra/tier-1s' | Where-Object { $_.display_name -like "$prefix*" }
        Write-Host ("  Tier-1s : " + ((@($t1s | ForEach-Object { $_.display_name }) | Sort-Object) -join ', '))
        Write-Host ("  Profiles: " + ((@(Get-TestProfiles | ForEach-Object { $_.display_name }) | Sort-Object) -join ', '))
    }

    'Remove' {
        $segs = Get-All '/infra/segments' | Where-Object { $_.display_name -like "$prefix*" }
        foreach ($s in $segs) {
            foreach ($bt in $bindingTypes) {
                foreach ($m in (Get-All "/infra/segments/$($s.id)/$bt")) { $null = Invoke-Nsx -Path "/infra/segments/$($s.id)/$bt/$($m.id)" -Method DELETE }
            }
            $null = Invoke-Nsx -Path "/infra/segments/$($s.id)" -Method DELETE
            Write-Host "  Removed segment $($s.display_name)"
        }
        foreach ($t in (Get-All '/infra/tier-1s' | Where-Object { $_.display_name -like "$prefix*" })) {
            $null = Invoke-Nsx -Path "/infra/tier-1s/$($t.id)" -Method DELETE
            Write-Host "  Removed Tier-1 $($t.display_name)"
        }
        foreach ($p in (Get-TestProfiles)) {
            $null = Invoke-Nsx -Path ($p.path) -Method DELETE
            Write-Host "  Removed profile $($p.display_name)"
        }
        Write-Host '  Done.' -ForegroundColor Green
    }
}
