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
| F1 | N4 to N4 | Create, Export the `NSXSM-T-Ovl-GW*` segments, rename them in the CSV, Import `-WhatIf`, Import `-Disconnected`, Show | Copies with Connectivity None, subnets and all profile bindings; cutover table names `NSXSM-T-T1` | 2026-11-16: **pass**. 2026-11-27, Export 2.4 / Import 2.7 on NSX 4.2.4.1: **pass**. Export via the search API 0:02 (4 segments, 5 profiles, GW1's 3 binding maps); `-NoSearch` gives the same segments, profiles and CSV, the binding maps differ only in property order. Copies `NSXSM-T-C-GW1/2` without gateway, subnets kept, 3 bindings on GW1. Import again: both segments and the 5 profiles skipped as existing, nothing written; the summary still ends "All items imported successfully!" |
| F2 | N4 to N4 | `Remove-NSXSegments.ps1` on the copies | Bindings first, port check, typed `YES`, removed | 2026-11-16: **pass**. 2026-11-27, Remove 1.5 (search route) on NSX 4.2.4.1, `-SegmentFilter 'NSXSM-T-C-*'`, profiles skipped with Enter: **pass**, 2 segments removed in 0:03 (GW1 with its 3 binding maps); a new export of `NSXSM-T-*` equals the one before F1 |
| F3 | N4 to NA | Export the whole set, Import into NSX 9.1.1 (gateway segments with `-Disconnected`, the others in separate runs, one transport zone per run) | Whole set imported; profiles on NSX 9's flat `/infra/<type>/` paths with all bindings | 2026-11-16: **pass** (Import 2.6). Not rerun with Import 2.7: NA not available |
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

**`-Confirm` and ports (2026-11-26, NB, functional set):**

| # | Steps | Result |
|---|---|---|
| C1 | Remove `-Confirm` on `Ovl-GW1` (five binding maps) and `Ovl-GW2`, typed `YES`, No for GW1, Yes for GW2 | **pass**: GW2 removed; GW1 kept with all five binding maps (checked with `-Mode Show`). The summary still says "All selected objects deleted successfully" with 1 OK and GW1 not counted |
| P1 | Powered-on dummy VM (no OS, one vNIC) on `Ovl-NoGW`; Remove `-WhatIf` on `Ovl-GW1`, `Ovl-NoGW`, `VLAN199`, with and without `-NoSearch` | **pass**: both routes warn "'NSXSM-T-Ovl-NoGW' has 1 port(s) still attached", nothing for the others. 2026-11-27 with Remove 1.7: **pass**, same result |
| P2 | Remove (typed `YES`) on `Ovl-NoGW` with the VM attached | **pass**: `[FAIL]` with NSX's message ("cannot be deleted as it has 1 VMs or VIFs attached"), exit 2. 2026-11-27 with Remove 1.7: **pass**, same message, exit 2 when started with `pwsh -File`; through `pwsh -Command "& ..."` the process reports 1 (PowerShell maps any non-zero code to 1 there; README notes it) |

After the dummy VM was deleted in vCenter, NSX kept its segment port
(`<vm>.vmx@<uuid>`) for several minutes and refused the segment DELETE;
the port was removed through the Policy API before the set's `-Mode Remove`.
On 2026-11-27 the port was gone about one minute after the VM was deleted;
the set's `-Mode Remove` then ran clean without touching the API by hand.

Not covered yet: the retry after a lagging search index.

**Shared helpers in `NSXSM-Common.ps1` (#11; Export 2.5, Import 2.8, Remove 1.6, Common 1.0), 2026-11-27, N4:**

| # | Steps | Result |
|---|---|---|
| R1 | A script alone in a folder; then next to a Common with version 0.9 | **pass**: "NSXSM-Common.ps1 not found next to this script" and "... older than 1.0", both exit 1 |
| R2 | F1 and F2 again with the new versions | **pass**: export equal to the Export 2.4 export of the same morning (segments, profiles, binding maps, CSV; transport zone names the same, in another order); Import `-WhatIf`, real Import, Import again (all skipped) and Remove as with 2.7 / 1.5; afterwards the set equals the start |
| R3 | Export on Windows PowerShell 5.1 | **pass**: search API route, same segments as on PowerShell 7 |

Not rerun for #11: the scale set (S0 to S3) and the NB cases; the moved code is the same text as before.

**Closing line and `-Confirm` (#13; Import 2.9, Remove 1.7), 2026-11-27, N4, copies `NSXSM-T-C-GW1/2`:**

| # | Steps | Result |
|---|---|---|
| R4 | Import of both copies (profiles already there), then the same import again | **pass**: "Imported 2 segment(s), 0 profile(s) and 3 binding map(s); 0 segment(s) and 5 profile(s) already on the target, left as is"; the second run "Nothing imported: 2 segment(s) and 5 profile(s) already on the target ..." |
| R5 | Remove `-Confirm`, Yes for GW1, No for GW2 | **pass**: GW1 `[OK]`, GW2 `[DECLINED] ... kept`; "1 of 2 selected object(s) deleted; 1 declined at -Confirm and kept", exit 0 |
| R6 | Import `-Confirm` with GW1 missing (three binding maps) and GW2 present; No for GW1 | **pass**: GW1 `[DECLINED]`, no questions for its binding maps, no cutover table; "Nothing imported: ...; 1 object(s) declined at -Confirm" |
| R7 | The same with `-WhatIf`, then `-Confirm` with Yes to all | **pass**: the dry run lists only GW1 under "Would be imported without a gateway"; the real run writes GW1 and its three binding maps, the cutover table holds only GW1, closing line "Imported 1 segment(s) ...; 1 segment(s) and 5 profile(s) already on the target ..." |

`-Confirm` answers came from stdin (`Y`/`N` per question). Set removed afterwards; the base set `NSXSM-T-*` untouched.

**Regression with Export 2.5 / Import 2.9 / Remove 1.7 / Common 1.0, 2026-11-27:**

| # | Lab | Steps | Result |
|---|---|---|---|
| X1 | N4 to NB | Cross-manager, instead of F3 while NA is away: the N4 export of `NSXSM-T-*` into NSX 9.0.2, overlay segments with `-Disconnected` into `overlay-vds01-mgmt-01a`, `VLAN199` in a second run into `nsx-vlan-transportzone`; the overlay run again; Remove of the set with its profiles (profile picker filtered on `/NSXSM-T`) | **pass**: 5 profiles on NSX 9's flat paths, 4 segments with Connectivity None, subnets and VLAN kept, all five profiles bound on `Ovl-GW1` (`-Mode Show`); the second run "Imported 1 segment(s) ...; 5 profile(s) already on the target", the rerun "Nothing imported: 3 segment(s) and 5 profile(s) ..."; Remove 4 segments then 5 profiles, NB clean |
| S0 | NB | Create and Remove of the scale set | **pass**: Create 1:06, Remove 2:57, nothing `NSXSM-*` left |
| S1 | NB | Export of the 500 `NSXSM-S-*` segments, search API and `-NoSearch` | **pass**: 0:02 and 1:52; segments, profiles, CSV and the 150 binding maps (segment, type, profile paths) identical |
| S2 | NB | Import into NB itself as `NSXSM-C-*`, `-Disconnected`: `-WhatIf`, real, again | **pass**: dry run 0:03 (500 segments and 150 bindings would be written, 5 profiles on target); real 1:08, 500 / 150 OK, closing line "Imported 500 segment(s) ...; 5 profile(s) already on the target"; again 0:03, "Nothing imported: 500 segment(s) and 5 profile(s) ..." |
| S3 | NB | Remove of the 500 `NSXSM-C-*` segments | **pass**: 1:06, 500 OK, none left |

P1/P2 rerun on 2026-11-27 (see the `-Confirm` and ports table). The dummy VM `NSXSM-T-Dummy` (1 vCPU, 128 MB, 16 MB thin disk, guest `otherGuest64`, no OS) was made with PowerCLI on the lab vCenter and deleted after the test.

Still open: F3 into NA (NSX 9.1.1) and the retry after a lagging search index.

## Open points

- The search API route (Export 2.4, Remove 1.5) ran against NSX 4.2.4.1 on
  2026-11-27 (F1, F2). F3 (N4 to NA) with Import 2.7 is still open, as long
  as NA is not available.
- S2 into a second NSX (NA to NB): dropped for this release (2026-11-26),
  NA is not available for some time. S2 ran into NB itself under new names
  (`NSXSM-C-*`); a cross-manager import of Import 2.7 is therefore not
  tested. F3 (N4 to NA, 2026-11-16) covered cross-manager with Import 2.6.
