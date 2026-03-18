# NSX Segment Migration Toolkit

A set of three PowerShell scripts to export, import, and clean up NSX segments and segment profiles across any NSX environment.

**Compatible with NSX 4.x and NSX 9.x.**

> By [Paul van Dieen](https://www.hollebollevsan.nl)

---

## Scripts

| Script | Purpose |
|--------|---------|
| `Export-NSXSegments.ps1` | Exports segments, custom profiles, and profile binding maps from a source NSX to a JSON + CSV file pair |
| `Import-NSXSegments.ps1` | Imports the JSON + CSV pair into a target NSX, with interactive transport zone selection, overlay validation, and name remapping |
| `Remove-NSXSegments.ps1` | Interactively selects and deletes segments and/or profiles, with a typed confirmation gate |

---

## Requirements

- PowerShell 5.1 or later (PS7 recommended)
- Network access to the NSX Manager REST API (port 443)
- NSX admin credentials

---

## Quick Start

### 1. Export from source NSX

```powershell
.\Export-NSXSegments.ps1 -NSXManager nsx-source.corp.local -SkipCertCheck
```

On first run you will be prompted for your username and password, then asked whether to save them for future runs. Select which segments to export from the interactive menu. Two files are written:

- `nsx-export_<timestamp>.json` — full object data for the importer
- `nsx-export_<timestamp>.csv` — name-mapping table; edit before importing

### 2. Edit the CSV

Open the CSV in Excel or any text editor. Fill in the `NewName` column for any object you want renamed on the target NSX. Leave `NewName` identical to `OldName` to keep the existing name.

| Type | Controls | Edit when... |
|------|----------|--------------|
| `Segment` | Segment display_name and id | You want a different name on the target |
| `SegmentProfile` | Profile name; binding paths update automatically | Profile should be renamed |
| `T1Gateway` | T1 gateway id in connectivity_path | Target NSX has a different gateway id |

### 3. Dry run on target NSX

```powershell
.\Import-NSXSegments.ps1 -NSXManager nsx-target.corp.local `
    -InputPath ./nsx-export_<timestamp>.json -WhatIf
```

### 4. Import

```powershell
.\Import-NSXSegments.ps1 -NSXManager nsx-target.corp.local `
    -InputPath ./nsx-export_<timestamp>.json -SkipCertCheck
```

The script will prompt you to:
- Select which segments to import
- Choose a transport zone from the target NSX
- Fill in any missing gateway or subnet values (overlay segments only)

### 5. Clean up (optional)

```powershell
.\Remove-NSXSegments.ps1 -NSXManager nsx-source.corp.local -SkipCertCheck
```

---

## Credentials

All three scripts handle credentials the same way:

**First run (no saved credential):**
```
  NSX username: admin
  NSX password: ********
  Save credential for future runs? (Y/N): Y
  Credential saved to: C:\Users\paul\.nsx_cred_nsx_source_corp_local.xml
```

**Subsequent runs (saved credential found):**
```
  Saved credential found for 'nsx-source.corp.local' (user: admin)
  [1] Use saved credential
  [2] Enter new credential and save over existing
  [3] Enter new credential without saving

  Select: 1
```

Credentials are saved per NSX Manager, so source and target environments each have their own file. The files are encrypted with Windows DPAPI and can only be decrypted by your Windows user account on the same machine.

To bypass the interactive flow entirely, pass a credential object directly:

```powershell
$cred = Import-Clixml "$env:USERPROFILE\.nsx_cred_nsx_source_corp_local.xml"
.\Export-NSXSegments.ps1 -NSXManager nsx-source.corp.local -Credential $cred -SkipCertCheck
```

---

## Export-NSXSegments.ps1

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-NSXManager` | Yes | — | FQDN or IP of the source NSX Manager |
| `-Credential` | No | Interactive | PSCredential for the NSX admin account |
| `-OutputBase` | No | `./nsx-export_<timestamp>` | Base path for output files (no extension) |
| `-SegmentFilter` | No | `*` | Wildcard filter on segment display_name |
| `-SkipCertCheck` | No | — | Bypass TLS certificate validation |

### What it exports

- Segments (selected interactively)
- All custom segment profiles (QoS, SpoofGuard, IP Discovery, MAC Discovery, Segment Security)
- Profile binding maps per segment:
  - `segment-discovery-profile-binding-maps` (IP Discovery, MAC Discovery)
  - `segment-security-profile-binding-maps` (Segment Security, SpoofGuard)
  - `segment-qos-profile-binding-maps` (QoS)

### Examples

```powershell
# Basic export
.\Export-NSXSegments.ps1 -NSXManager nsx.corp.local -SkipCertCheck

# Filter segments and set output path
.\Export-NSXSegments.ps1 -NSXManager nsx.corp.local `
    -SegmentFilter "prod-*" `
    -OutputBase ./exports/prod-migration `
    -SkipCertCheck
```

---

## Import-NSXSegments.ps1

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-NSXManager` | Yes | — | FQDN or IP of the target NSX Manager |
| `-Credential` | No | Interactive | PSCredential for the NSX admin account |
| `-InputPath` | Yes | — | Path to the `.json` file from Export |
| `-MappingPath` | No | Same path as InputPath with `.csv` extension | Explicit path to the CSV name-mapping file |
| `-TransportZoneId` | No | Interactive menu | Transport zone id to apply to all imported segments |
| `-SkipCertCheck` | No | — | Bypass TLS certificate validation |
| `-WhatIf` | No | — | Preview all changes without making any API calls |

### Import order

Objects are always imported in this sequence to satisfy dependencies:

1. **Custom segment profiles** — all profiles from the export (idempotent PATCH, safe to re-run)
2. **Segments** — only the ones selected in the menu
3. **Profile binding maps** — applied per-segment immediately after each segment is created

### Transport zone selection

After connecting, an interactive menu lists all transport zones on the target NSX. Select one to apply it to all imported segments, or press Enter to keep the transport zone from the export file. Supply `-TransportZoneId` on the command line to skip the menu.

### Overlay segment validation

When the selected transport zone is `OVERLAY_BACKED`, the script checks each segment for the two fields NSX requires:

- `connectivity_path` — T0 or T1 gateway connection
- `subnets` — gateway IP and prefix (e.g. `192.168.10.1/24`)

Missing values trigger an interactive prompt before any import begins. VLAN-backed segments skip this step entirely.

### Examples

```powershell
# Standard import
.\Import-NSXSegments.ps1 -NSXManager nsx-target.corp.local `
    -InputPath ./nsx-export_20260101_120000.json -SkipCertCheck

# Skip transport zone menu
.\Import-NSXSegments.ps1 -NSXManager nsx-target.corp.local `
    -InputPath ./exports/prod-migration.json `
    -TransportZoneId tz-overlay-prod `
    -SkipCertCheck

# Dry run
.\Import-NSXSegments.ps1 -NSXManager nsx-target.corp.local `
    -InputPath ./nsx-export_20260101_120000.json -WhatIf
```

---

## Remove-NSXSegments.ps1

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-NSXManager` | Yes | — | FQDN or IP of the NSX Manager |
| `-Credential` | No | Interactive | PSCredential for the NSX admin account |
| `-SegmentFilter` | No | `*` | Wildcard filter on segment display_name |
| `-SkipCertCheck` | No | — | Bypass TLS certificate validation |
| `-WhatIf` | No | — | Preview all deletions without making any API calls |

### Deletion order

The script enforces the correct deletion sequence automatically:

1. **Profile binding maps** — removed silently from each segment before the segment DELETE
2. **Segments** — deleted after their binding maps are cleared
3. **Profiles** — deleted after all segments are gone

### Safety features

- Independent menus for segments and profiles — press Enter at either to skip that category
- Port check before confirmation — segments with attached ports are flagged as a warning
- Typed `YES` confirmation required before any DELETE is executed
- Full `-WhatIf` support

### Examples

```powershell
# Interactive cleanup
.\Remove-NSXSegments.ps1 -NSXManager nsx.corp.local -SkipCertCheck

# Filter segments shown in the menu
.\Remove-NSXSegments.ps1 -NSXManager nsx.corp.local `
    -SegmentFilter "test-*" -SkipCertCheck

# Dry run
.\Remove-NSXSegments.ps1 -NSXManager nsx.corp.local -SkipCertCheck -WhatIf
```

---

## NSX Version Compatibility

| Path format | NSX version |
|-------------|-------------|
| `/infra/segment-profiles/<type>/<id>` | NSX 4.x (legacy) |
| `/infra/<type>/<id>` | NSX 9.x (flat) |

All three scripts try both path formats automatically and use whichever responds. The path that succeeds on GET is the same path used for subsequent PATCH and DELETE calls on the same object.

---

## Certificate Notes

`-SkipCertCheck` bypasses TLS validation and works for self-signed certificates. If your NSX uses a certificate signed by an internal CA, you may still see validation errors because Windows cannot build a trust chain to the CA root. The fix is to import your CA certificate into the Windows Trusted Root store:

```powershell
Import-Certificate -FilePath "your-internal-ca.cer" `
    -CertStoreLocation Cert:\LocalMachine\Root
```

Once your CA is trusted, `-SkipCertCheck` is no longer needed.

---

## Changelog

### v2.1 — Export / v2.2 — Import / v1.2 — Remove
- Added built-in credential save and reset. On first run credentials are prompted and optionally saved per NSX Manager using Windows DPAPI encryption. Subsequent runs offer to reuse, overwrite, or ignore the saved credential.
- Replaced `Get-Credential` with `Read-Host` prompts to fix null credential errors in non-interactive PowerShell hosts.
- Fixed `PropertyNotFoundException` crash under `Set-StrictMode -Version Latest` when `Get-Credential` returned null.

### v2.1 — Import
- Added interactive transport zone selection menu after connecting to the target NSX.
- Added overlay segment validation: prompts for missing gateway and subnet before import begins when an OVERLAY_BACKED transport zone is selected.

### v2.0 — Export / Import
- Full rewrite with clean comments and consistent style.
- Added `Get-AllPages` pagination support.
- Profile binding maps now exported and imported via typed child paths (`segment-discovery-profile-binding-maps`, `segment-security-profile-binding-maps`, `segment-qos-profile-binding-maps`).
- NSX 4.x and 9.x profile path formats handled automatically.
- Profile path remap table ensures binding maps reference the correct renamed paths on the target.

### v1.1 — Remove
- Added port count check before confirmation prompt.
- Fixed extra confirmation prompts caused by `ConfirmImpact = 'High'`.
- Binding map deletion no longer triggers `ShouldProcess` prompts.

### v1.0 — Remove
- Initial release of Remove-NSXSegments.ps1.

---

## License

MIT

---

*More posts and tools at [hollebollevsan.nl](https://www.hollebollevsan.nl)*
