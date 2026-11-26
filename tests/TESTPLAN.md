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

| # | Steps | Expected | Result |
|---|---|---|---|
| S0 | Create and Remove of the set itself | 500 segments, 3 Tier-1s, 5 profiles, 50 segments with bindings; Remove leaves nothing | NA 2026-11-19: **pass**, Create 1:23, Remove clean. NB 2026-11-26: **pass**, Create 1:09 |
| S1 | Export all `NSXSM-S-*` segments | One CSV and profile export; duration and progress noted | NB 2026-11-26: **pass**. Export 2.3: 1:52 (three GETs per segment for the binding maps). Export 2.4: 0:02 via the search API, `-NoSearch` 1:53; all three exports gave the same 150 binding maps with the same profile paths and identical segments |
| S2 | Import the export (NA was down: into NB itself, segments renamed `NSXSM-C-*` in the CSV), `-WhatIf` first | All 500 planned; then imported | NB 2026-11-26: **pass**. Without `-Disconnected` the 300 gateway segments fail on the same NSX (subnet overlaps the original on the same Tier-1, expected). With `-Disconnected`: Import 2.6 0:58, 4285 console lines, no exit code; Import 2.7 1:03, 2272 lines, exit 0, the 10 profiles already on the target skipped. Without renames 2.7 skips all 500 as existing. A forced overlap error shows NSX's message and exits 2 |
| S3 | `Remove-NSXSegments.ps1` on 500 imported segments | Port check and removal at scale; duration noted | NB 2026-11-26: **pass**. Remove 1.4: 3:34. Remove 1.5: 1:13, no segments or binding maps left under `NSXSM-C-*`. `-NoSearch` on the functional set: pass. Profiles still in use: NSX's reason shown, exit 2 |

**Pickers (2026-11-26, NB and the S1 export of 500 segments):** shortened
list above 50, filters `/VLAN` (100 of 500), `/no gateway` (100 of 500) and
`/TZ:` with the zone name (Export 2.4 stores the names; an older export
shows the id), renumbering, ranges, `all` and `*`, `reset`, a filter that
matches nothing, bad input and out-of-range numbers, `cancel` (Import stops
before connecting, Remove deletes nothing), Remove's Enter-to-skip, and
Import `-SegmentFilter`: **pass**, on PowerShell 7 and (Import picker) 5.1.

Not covered yet: the port warning with a real port on a selected segment
(NB had no ports on test segments; search and per-segment counts agreed on
"0"), the retry after a lagging search index, and `-Confirm` answered No.

## Open points

- N4 is the home lab and often powered off; the 4.x source cases date from
  2026-11-16. The search API route (Export 2.4, Remove 1.5) has not run
  against NSX 4.x yet: run F1 and F3 again when N4 is up.
- S2 into a second NSX (NA to NB) when NA is reachable again.
