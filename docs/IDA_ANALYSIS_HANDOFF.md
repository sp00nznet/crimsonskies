# IDA Pro Cross-Validation — Crimson Skies

Headless IDA Pro 9.1 analysis of `analysis/CRIMSON_decrypted.exe` (VC6/MFC42, PE32,
image base `0x400000`), cross-checked against `config/functions.json`. The PE loads
natively in IDA and aligns with the recomp's addresses directly — no rebasing.

## Headline: the recomp is missing ~770 C++ virtual methods 🎯

| Metric | Value |
|---|---|
| IDA functions (independent analysis) | **7,464** |
| Recomp `functions.json` | 6,232 (+155 manual) |
| Overlap | 5,938 |
| **IDA-only (not in recomp)** | **1,526** |
| Recomp-only (IDA: not a function) | 294 — **only 3 are data false-positives** |

### The critical gap: vtables (`crimson_missed_virtuals.csv`)
IDA found **179 vtables** (runs of ≥3 consecutive function pointers in read-only
data) targeting **900 virtual methods** — of which **773 are absent from
`functions.json`**. Adjustor-thunk entries among them confirm these are genuine
C++ virtual dispatch targets (a small number may be CRT init-table entries).

**Root cause:** the recomp's function discovery is call-graph based (recursive from
entry + direct calls). It does **not parse vtables**, so virtual methods reached
*only* through a vtable pointer are never discovered. At runtime, the first virtual
call into one of these ~770 functions hits an untranslated address → crash. Given
the project is in Phase 4 (runtime bringup), this is likely a major source of the
bringup instability.

**Fix:** add a vtable-scan pass to discovery (scan `.rdata` for runs of code
pointers; add every target as a function entry), **or** import IDA's function set
directly. `crimson_missed_virtuals.csv` lists all 773 with addresses — drop them
into `functions.json` / `manual_functions.json` and re-run codegen.

## Free symbol enrichment: 347 library names (`crimson_ida_names.csv`)
IDA's FLIRT signatures (VC6 CRT, MFC42, C++ std, ATL) named **347** functions the
recomp has as bare `sub_` — e.g. `CMFCToolBarInfo::ctor`, `CDaoRecordset::ResetCursor`,
`ios_base::dtor`, `DirectSoundCreate`. All 347 are new names; adopt the
non-CRT ones to make the lifted C readable.

## Recomp-only (294) — mostly fine
- **238 mid_function** — recomp splits finer than IDA (tail-calls / shared code); like
  other projects, generally legitimate, not errors.
- **53 code_orphan** — code IDA didn't wrap as a function; worth a glance.
- **3 data** — recomp emitted a function at a data address (genuine false positives):
  see `crimson_recomp_only.csv`.

## Artifacts (`E:\ida\work\crimsonskies\`)
- `crimson_missed_virtuals.csv` — **773 missed virtual methods** (the priority fix)
- `crimson_ida_only.csv` — all 1,526 IDA-only, classified (library/called/vtable/noref)
- `crimson_ida_names.csv` — 347 FLIRT names to adopt
- `crimson_recomp_only.csv` — 294 recomp-only, classified

## Reproduce
```
py -3.11 tools/crimson_gap.py      CRIMSON_decrypted.exe <config_dir> <out>
py -3.11 tools/crimson_vtables.py  CRIMSON_decrypted.exe <config_dir> <out>
```

> Note: the shared Zipper **GameZ/GOS engine** means the vtable-discovery gap (and
> this whole workflow) likely applies to **MechWarrior 3** and **Recoil** too.
