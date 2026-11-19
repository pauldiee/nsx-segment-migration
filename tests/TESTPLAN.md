# nsx-segment-migration test plan

How to test `Export-NSXSegments.ps1`, `Import-NSXSegments.ps1` and
`Remove-NSXSegments.ps1` in a lab: which lab, which test set, which cases,
and what came out. Labs are named by code only; addresses live outside this
repository.

## Labs

| Code | What | Role in the tests |
|---|---|---|
| **N4** | NSX 4.2.4.1, home lab, no hosts | Source (NSX 4.x) |
| **NA** | NSX 9.1.1, management NSX of the VCF 9.1.1 lab | Target; scale set |
| **NB** | NSX 9.0.2, management NSX of the VCF 9.0.2 lab, no licence | Second target (DFW blocked without licence; segments work) |

## Test sets

| Script | What it builds | Cleanup |
|---|---|---|
| `New-NSXSMTestSet.ps1` | Functional set: five custom segment profiles (QoS, SpoofGuard, IP Discovery, MAC Discovery, Segment Security), Tier-1 `NSXSM-T-T1` without Edge cluster, overlay segments `Ovl-GW1` (all five profiles) and `Ovl-GW2` with a gateway, `Ovl-NoGW`, and `VLAN199` | `-Mode Remove` |
| `New-NSXSMScaleSet.ps1` | Scale set: the five profiles as `NSXSM-S-*`, `-Tier1Count` Tier-1s (default 3, no Edge cluster), `-SegmentCount` segments (default 500): 60% overlay with a /24 gateway on one of the Tier-1s, 20% overlay without gateway, 20% VLAN (1000 and up); every tenth segment with all five profiles bound | `-Mode Remove` |

## Test cases

### A. Functional (New-NSXSMTestSet.ps1)

| # | Lab | Steps | Expected | Result |
|---|---|---|---|---|
| F1 | N4 to N4 | Create, Export the `NSXSM-T-Ovl-GW*` segments, rename them in the CSV, Import `-WhatIf`, Import `-Disconnected`, Show | Copies with Connectivity None, subnets and all profile bindings; cutover table names `NSXSM-T-T1` | 2026-11-16: **pass** |
| F2 | N4 to N4 | `Remove-NSXSegments.ps1` on the copies | Bindings first, port check, typed `YES`, removed | 2026-11-16: **pass** |
| F3 | N4 to NA | Export the whole set, Import into NSX 9.1.1 (gateway segments with `-Disconnected`, the others in separate runs, one transport zone per run) | Whole set imported; profiles on NSX 9's flat `/infra/<type>/` paths with all bindings | 2026-11-16: **pass** |
| F4 | NA | Remove the imported set | Removed | 2026-11-16: **pass** |

### B. Scale (New-NSXSMScaleSet.ps1)

| # | Steps | Expected | Result (NA, 2026-11-19) |
|---|---|---|---|
| S0 | Create and Remove of the set itself | 500 segments, 3 Tier-1s, 5 profiles, 50 segments with bindings; Remove leaves nothing | **pass**: Create 1:23, Remove clean |
| S1 | Export all `NSXSM-S-*` segments | One CSV and profile export; duration and progress noted | not run yet |
| S2 | Import the export into a second NSX (NA to NB), `-WhatIf` first | All 500 planned; then imported per transport zone | not run yet |
| S3 | `Remove-NSXSegments.ps1` on 500 imported segments | Port check and removal at scale; duration noted | not run yet |

## Open points

- S1 to S3: the scale runs of the scripts themselves.
- N4 is the home lab and often powered off; the 4.x source cases date from
  2026-11-16.
