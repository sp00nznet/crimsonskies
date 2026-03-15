# Crimson Skies — Static Recompilation

A static recompilation of **Crimson Skies** (2000) by Zipper Interactive / Microsoft, targeting modern Windows with native x86 execution and a modern graphics pipeline.

This is a game preservation project. Crimson Skies is a beloved arcade flight combat game with **zero** existing preservation efforts — no source port, no decompilation, no community engine. The original game suffers from SafeDisc DRM (non-functional on Windows 10+), broken hardware acceleration on modern GPUs, and text rendering corruption. It deserves better.

> *"Welcome to the world of air combat, 1930s style."*

## Why This Game?

- **No one else is doing this.** Unlike Doom, Quake, or even X-Wing Alliance, Crimson Skies has no community source port or reverse engineering project
- **It's broken on modern systems.** SafeDisc DRM was killed by Microsoft in 2015. Even with workarounds (csfix, dgVoodoo2), the game is held together with duct tape
- **The engine is shared.** Crimson Skies uses the Zipper Interactive **GameZ/GOS engine** — the same engine as MechWarrior 3 (1999) and Recoil (1999). A successful recompilation could unlock all three games
- **It's a genuinely great game** that deserves to be playable for another 25 years

## Project Status

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 0** | **Complete** | Binary analysis, PE parsing, SafeDisc decryption |
| **Phase 1** | **Complete** | Function discovery (6,081 functions from 6,083 entries) |
| **Phase 2** | **Complete** | x86-to-C code generation (821,533 lines, 44 MB, 0 errors) |
| **Phase 3** | **Complete** | Compilation and linking (0 errors, 18.4 MB exe, runs) |
| Phase 4 | **Next** | Runtime bringup — memory mapping, import bridges, CRT init |
| Phase 5 | Pending | Win32/DirectX HAL — COM mocks for DDraw/D3D/DInput/DSound |
| Phase 6 | Pending | GOS engine abstraction — rendering, audio, input |
| Phase 7 | Pending | Asset loading — ROF archives, ZBD files, CAB extraction |
| Phase 8 | Pending | Menu/UI rendering |
| Phase 9 | Pending | Flight model, mission logic, full gameplay |
| Phase 10 | Pending | Modern rendering backend (D3D11/Vulkan) |

## Binary Analysis

| Property | Value |
|----------|-------|
| **Target** | `CRIMSON.ICD` (2.46 MB) |
| **Compiler** | Visual C++ 6.0 (Visual Studio 98) |
| **Build Date** | 2000-11-18 |
| **Architecture** | x86-32, PE32, image base 0x00400000 |
| **Code (.text)** | 0x00401000 - 0x006024BD (2.0 MB) |
| **Data (.data)** | 0x00619000 - 4 MB virtual |
| **Copy Protection** | SafeDisc v1.50 (BoG_ marker, ICD format) |
| **Relocations** | Present (.reloc section) |
| **PDB Path** | `D:\zipper\CrimsonRun\run\Crimson.pdb` |
| **Functions** | 6,081 (discovered from 6,083 entry points) |
| **Lines of C** | 821,533 (44 MB across 13 source files) |
| **Code Gen Errors** | 0 |
| **Code Gen Time** | 8.5 seconds |
| **Compile Errors** | 0 |
| **Link Errors** | 0 |
| **Executable Size** | 18.4 MB |
| **Post-Gen Fixes** | 792 tail calls, 3 FPU cmp, 2 bogus calls, 1 stub |

### Recompilation Statistics

| Metric | Value |
|--------|-------|
| Functions recompiled | 6,081 |
| Total lines of C | 821,533 |
| Generated code size | 44.0 MB |
| Source files | 13 + header + dispatch table |
| Code generation time | 8.5 seconds |
| Compilation errors | 0 (code gen) |

### Engine: Zipper Interactive GameZ / GOS

The engine's internal framework is called **GOS** (Game Operating System), providing:
- Text rendering (`gos_LoadFont`, `gos_TextDraw`)
- Scripting (`gosScript`) — an interpreted scripting language for mission logic
- Surface/pane management
- Rendering abstraction over Direct3D Immediate Mode

PDB path confirms the source tree: `D:\zipper\CrimsonRun\`

### Import Summary (461 functions from 19 DLLs)

| DLL | Functions | Purpose |
|-----|-----------|---------|
| KERNEL32.dll | 117 | Core Win32 |
| USER32.dll | 94 | Window management |
| GDI32.dll | 22 | Font/text rendering |
| MFC42.DLL | 64 | Microsoft Foundation Classes |
| MSVCRT.dll | 62 | C Runtime |
| MSVCP60.dll | 10 | C++ Standard Library |
| IFC21.dll | 19 | Immersion force feedback |
| WINMM.dll | 14 | Multimedia (mixer, MCI) |
| AVIFIL32.dll | 9 | AVI video playback |
| DDRAW.dll | 2 | DirectDraw |
| DINPUT.dll | 1 | DirectInput |
| DSOUND.dll | 1 | DirectSound |
| DPLAYX.dll | 1 | DirectPlay (multiplayer) |
| zTiff.dll | 5 | TIFF image loading |
| ROFFILE.dll | ~8 | ROF archive file system |
| ole32.dll | 3 | COM initialization |
| SHELL32.dll | 3 | Shell operations |
| ADVAPI32.dll | 6 | Registry |
| comdlg32.dll | 2 | File dialogs |

### Asset Formats

| Format | Extension | Purpose | Tooling |
|--------|-----------|---------|---------|
| **ROF** | .ROF | Archive containers with directory tree | ROFFILE.dll (game), mech3ax (community) |
| **ZBD** | .ZBD | Data archives (sounds, textures, scripts, models) | mech3ax extracts WAV/PNG/JSON |
| **CAB** | .CAB | Per-chapter compressed data (C1-C5) | Standard Microsoft Cabinet |
| **GW** | embedded | gosScript mission/UI scripts | Interpreter in INTERP.ZBD |
| **MPG** | .MPG | Cutscene video (MPEG-1) | Standard codecs |
| **TGA/BMP** | .TGA/.BMP | Textures and UI graphics | Standard formats |
| **TIFF** | via zTiff.dll | Additional image format support | zTiff.dll |

## Architecture

```
crimsonskies/
├── tools/pcrecomp/         # Shared recompilation toolkit (submodule)
├── analysis/               # PE analysis results, function maps
│   ├── functions.json      # Function address/size/block map
│   └── pe_analysis.json    # PE header analysis
├── src/
│   ├── game/
│   │   ├── main.c          # Entry point, VEH handler, manual overrides
│   │   ├── imports.c       # Win32/DirectX import bridges
│   │   ├── com_mocks.c     # COM mock objects (DDraw, D3D, DInput, DSound)
│   │   └── recomp/
│   │       ├── recomp_types.h  # Register model, memory macros
│   │       └── gen/            # Auto-generated C code (gitignored)
│   └── hal/
│       └── renderer.c      # Modern rendering backend
├── config/
│   └── pe_analysis.json    # PE metadata for code generator
├── CMakeLists.txt
└── README.md
```

### Current Runtime Output

```
Crimson Skies Static Recompilation v0.1
=======================================
Binary: CRIMSON.ICD (Zipper Interactive, 2000)
Engine: GameZ/GOS
Functions: 6081

Setup complete. Runtime bringup pending.
```

## Building

### Prerequisites

- **CMake** 3.20+
- **Visual Studio 2022** (MSVC, x86/Win32 target)
- **Python 3.10+** with `capstone`, `pefile`
- A legally owned copy of Crimson Skies

### Code Generation

```bash
# Step 1: Obtain decrypted binary (see SafeDisc section below)
# Step 2: Generate recompiled code
python -m tools.pcrecomp.tools --exe CRIMSON_decrypted.exe --all -o src/recomp/gen

# Step 3: Build
cmake -B build -G "Visual Studio 17 2022" -A Win32
cmake --build build --config Release
```

### SafeDisc Decryption

The retail CRIMSON.ICD has SafeDisc v1.50 encryption (7.8 bits/byte entropy in .text). Options:

1. **Memory dump** (recommended): Use `tools/pcrecomp/tools/drm/safedisc_dump.py` with SafeDiscShim to launch the game and dump decrypted code from memory
2. **csfix**: The community csfix patch includes a pre-decrypted executable
3. **unSafeDisc**: Static decryption tool for SafeDisc v1 ICD files

## Related Projects

- [mech3ax](https://github.com/TerranMechworks/mech3ax) — Rust-based asset extractor for MechWarrior 3 and Crimson Skies (ZBD/ROF formats)
- [pcrecomp](https://github.com/sp00nznet/pcrecomp) — Shared PC static recompilation toolkit
- [xwa](https://github.com/sp00nznet/xwa) — X-Wing Alliance recompilation (reference implementation)

Part of the [sp00nznet](https://github.com/sp00nznet) recompilation collection.

## Legal

This is a game preservation project. You must own a legal copy of Crimson Skies to use this.
No copyrighted game assets are included in this repository.

## Contributing

This project is in early stages. If you're interested in helping preserve Crimson Skies:

- **Reverse engineers**: Function identification, vtable mapping, string cross-references
- **Graphics programmers**: D3D Immediate Mode → modern D3D11/Vulkan translation
- **Flight sim fans**: Flight model tuning, mission script documentation
- **Modders**: ROF/ZBD format documentation, asset pipeline tools

Open an issue or join the discussion!
