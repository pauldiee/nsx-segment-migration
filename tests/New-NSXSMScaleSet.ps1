#Requires -Version 7.4

<#
.SYNOPSIS
    Builds or removes a large throwaway set of NSX segments in a LAB NSX
    Manager, to test Export-, Import- and Remove-NSXSegments.ps1 at scale.

.DESCRIPTION
    Lab use only. Every object it creates is named NSXSM-S-*, and Remove only
    deletes NSXSM-S-* objects.

    Create builds:
        Profiles:  NSXSM-S-QoS, NSXSM-S-SpoofGuard, NSXSM-S-IPDisc,
                   NSXSM-S-MACDisc, NSXSM-S-SegSec (one of each type)
        Tier-1s:   -Tier1Count gateways NSXSM-S-T1-<n> (default 3), no NSX
                   Edge cluster (distributed only), advertising connected
                   segments
        Segments:  -SegmentCount segments (default 500), NSXSM-S-<nnnn>, in
                   turn:
                     60%  overlay, connected to one of the Tier-1s, a /24
                          gateway in 10.200.0.0/16 - 10.203.0.0/16
                     20%  overlay without gateway
                     20%  VLAN segment, VLAN 1000 and up
                   Every tenth segment gets all five custom profiles bound.
    Running Create again adds what is missing (PATCH is idempotent).

    Remove deletes the bindings, the segments, the Tier-1s and the profiles
    of the set, in that order.

.PARAMETER NSXManager
    FQDN or IP of the LAB NSX Manager.

.PARAMETER Mode
    Create or Remove.

.PARAMETER SegmentCount
    Number of segments (Create). Default 500.

.PARAMETER Tier1Count
    Number of Tier-1 gateways (Create). Default 3.

.PARAMETER Credential
    NSX admin credential. Defaults to the toolkit's own file:
    <manager>.cred in the repo root (Common 1.2), creds\<manager>.cred, or the older
    %USERPROFILE%\.nsx_cred_<manager>.xml.

.PARAMETER SkipCertCheck
    Accept a self-signed lab certificate.

.EXAMPLE
    .\tests\New-NSXSMScaleSet.ps1 -NSXManager nsx-lab.lab.local -Mode Create -SkipCertCheck

.EXAMPLE
    .\tests\New-NSXSMScaleSet.ps1 -NSXManager nsx-lab.lab.local -Mode Remove -SkipCertCheck

.NOTES
    Script   : New-NSXSMScaleSet.ps1
    Version  : 0.1.1
    Author   : Paul van Dieen
    Blog     : https://www.hollebollevsan.nl
    Requires : PowerShell 7.4+ (no PowerCLI needed)
    Tested   : Lab, 2026-11-19: NSX 9.1.1 (Holodeck lab A), Create and Remove
#>

<# CHANGELOG
v0.1.1  2026-11-27  Paul van Dieen
- Reads the credential from <manager>.cred next to the toolkit scripts
  (NSXSM-Common 1.2, #20) first, then creds\ and the user profile.

    v0.1.0  2026-11-19  Paul van Dieen
        - Initial version: Create and Remove of a large segment set for scale
          tests of the nsx-segment-migration scripts (#8)
#>

param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][ValidateSet('Create', 'Remove')][string]$Mode,
    [ValidateRange(1, 10000)][int]$SegmentCount = 500,
    [ValidateRange(1, 20)][int]$Tier1Count = 3,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SkipCertCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptVersion = '0.1.1'
$scriptAuthor  = 'Paul van Dieen'
$scriptBlogUrl = 'https://www.hollebollevsan.nl'
$prefix        = 'NSXSM-S-'

Write-Host ('=' * 62) -ForegroundColor DarkCyan
Write-Host ('  New-NSXSMScaleSet.ps1' + (' ' * 24) + "v$scriptVersion") -ForegroundColor Cyan
Write-Host "  $scriptAuthor - $scriptBlogUrl" -ForegroundColor Gray
Write-Host '  LAB USE ONLY - touches NSXSM-S-* objects only' -ForegroundColor Yellow
Write-Host ('=' * 62) -ForegroundColor DarkCyan

if (-not $Credential) {
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
    if ($out.Count) { $out }
}

function Get-StatusCode { param($Err) try { [int]$Err.Exception.Response.StatusCode } catch { 0 } }

function Say { param([string]$Text, [string]$Color = 'Cyan') Write-Host "  $Text" -ForegroundColor $Color }

$profiles = [ordered]@{
    'QoS'        = @{ Type = 'qos-profiles';              Body = @{ class_of_service = 3 } }
    'SpoofGuard' = @{ Type = 'spoofguard-profiles';       Body = @{} }
    'IPDisc'     = @{ Type = 'ip-discovery-profiles';     Body = @{} }
    'MACDisc'    = @{ Type = 'mac-discovery-profiles';    Body = @{ mac_learning_enabled = $true } }
    'SegSec'     = @{ Type = 'segment-security-profiles'; Body = @{} }
}

function Set-Profile {
    param([string]$Name, [string]$Type, [hashtable]$Body)
    $b = @{ display_name = $Name; description = 'nsx-segment-migration scale set' } + $Body
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

function Get-SetProfiles {
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
Say "Connected to $NSXManager (NSX $version)" Green

switch ($Mode) {
    'Create' {
        $started = Get-Date
        $tzs  = Get-All '/infra/sites/default/enforcement-points/default/transport-zones'
        $ovl  = $tzs | Where-Object { $_.tz_type -like 'OVERLAY*' } | Sort-Object { -not $_.is_default } | Select-Object -First 1
        $vlan = $tzs | Where-Object { $_.tz_type -like 'VLAN*' }    | Sort-Object { -not $_.is_default } | Select-Object -First 1
        if (-not $ovl -or -not $vlan) { throw 'Need an overlay and a VLAN transport zone on this NSX Manager.' }
        Say "Transport zones: overlay '$($ovl.display_name)', VLAN '$($vlan.display_name)'"

        $pp = @{}
        foreach ($k in $profiles.Keys) { $pp[$k] = Set-Profile -Name "$prefix$k" -Type $profiles[$k].Type -Body $profiles[$k].Body }
        Say "Profiles: $($profiles.Count)"

        $t1s = @()
        for ($t = 1; $t -le $Tier1Count; $t++) {
            $id = "${prefix}T1-$t"
            $null = Invoke-Nsx -Path "/infra/tier-1s/$id" -Method PATCH -Body @{
                display_name = $id; description = 'nsx-segment-migration scale set'; route_advertisement_types = @('TIER1_CONNECTED') }
            $t1s += "/infra/tier-1s/$id"
        }
        Say "Tier-1s: $Tier1Count (no Edge cluster)"

        $kinds = @{ gw = 0; nogw = 0; vlan = 0 }
        $bound = 0
        for ($i = 1; $i -le $SegmentCount; $i++) {
            $id = '{0}{1:D4}' -f $prefix, $i
            $body = @{ display_name = $id; description = 'nsx-segment-migration scale set' }
            switch ($i % 5) {
                { $_ -in 1, 2, 3 } {
                    # 10.200.0.0/16 to 10.203.0.0/16: room for 1024 /24 gateways
                    $n = $i - 1
                    $body.transport_zone_path = $ovl.path
                    $body.connectivity_path   = $t1s[$i % $t1s.Count]
                    $body.subnets = @(@{ gateway_address = ('10.{0}.{1}.1/24' -f (200 + [int][Math]::Floor($n / 256) % 4), ($n % 256)) })
                    $kinds.gw++
                }
                4 { $body.transport_zone_path = $ovl.path; $kinds.nogw++ }
                0 { $body.transport_zone_path = $vlan.path; $body.vlan_ids = @([string](1000 + ($i % 3000))); $kinds.vlan++ }
            }
            $null = Invoke-Nsx -Path "/infra/segments/$id" -Method PATCH -Body $body
            if ($i % 10 -eq 0) {
                $sp = "/infra/segments/$id"
                $null = Invoke-Nsx -Path "$sp/segment-qos-profile-binding-maps/${prefix}qos" -Method PATCH -Body @{ qos_profile_path = $pp['QoS'] }
                $null = Invoke-Nsx -Path "$sp/segment-discovery-profile-binding-maps/${prefix}disc" -Method PATCH -Body @{
                    ip_discovery_profile_path = $pp['IPDisc']; mac_discovery_profile_path = $pp['MACDisc'] }
                $null = Invoke-Nsx -Path "$sp/segment-security-profile-binding-maps/${prefix}sec" -Method PATCH -Body @{
                    segment_security_profile_path = $pp['SegSec']; spoofguard_profile_path = $pp['SpoofGuard'] }
                $bound++
            }
            if ($i % 50 -eq 0) {
                Write-Progress -Activity 'Creating segments' -Status "$i of $SegmentCount" -PercentComplete ([int](100 * $i / $SegmentCount))
                Say "  $i of $SegmentCount"
            }
        }
        Write-Progress -Activity 'Creating segments' -Completed
        Say ("Done in {0:mm\:ss}: {1} segments ({2} with gateway, {3} without, {4} VLAN), {5} with all custom profiles." -f ((Get-Date) - $started), $SegmentCount, $kinds.gw, $kinds.nogw, $kinds.vlan, $bound) Green
    }

    'Remove' {
        $segs = @(Get-All '/infra/segments' | Where-Object { $_.display_name -like "$prefix*" })
        $no = 0
        foreach ($s in $segs) {
            foreach ($bt in $bindingTypes) {
                foreach ($m in (Get-All "/infra/segments/$($s.id)/$bt")) { $null = Invoke-Nsx -Path "/infra/segments/$($s.id)/$bt/$($m.id)" -Method DELETE }
            }
            $null = Invoke-Nsx -Path "/infra/segments/$($s.id)" -Method DELETE
            $no++
            if ($no % 50 -eq 0) { Say "  $no of $($segs.Count) segments removed" }
        }
        Say "Removed $($segs.Count) segment(s)." Yellow
        $t1 = @(Get-All '/infra/tier-1s' | Where-Object { $_.display_name -like "$prefix*" })
        foreach ($t in $t1) { $null = Invoke-Nsx -Path "/infra/tier-1s/$($t.id)" -Method DELETE }
        Say "Removed $($t1.Count) Tier-1(s)." Yellow
        $pr = @(Get-SetProfiles)
        foreach ($p in $pr) { $null = Invoke-Nsx -Path ($p.path) -Method DELETE }
        Say "Removed $($pr.Count) profile(s)." Yellow
    }
}
