# Crimson Skies Static Recompilation — Master Plan

## The Big Picture

We're turning a 2.5MB Win32 executable from the year 2000 into a living, buildable
C codebase that runs natively on modern systems. The game has ~5,865 functions and
~732,000 x86 instructions. We have a battle-tested pipeline that has already
successfully recompiled X-Wing Alliance (2,701 functions → running game with D3D11).

Crimson Skies is roughly **2x the size** of XWA, but shares the same era (MSVC 6.0,
DirectX 6, Win32 GUI) and many of the same patterns. The XWA project proved this
approach works end-to-end.

## Phase Breakdown

### Phase 0: Binary Analysis ✅ COMPLETE

- [x] Obtain game disc image
- [x] Extract CRIMSON.ICD (2,580,578 bytes)
- [x] Identify SafeDisc v1.50 encryption (BoG_ marker, 7.8 bits/byte entropy)
- [x] Obtain decrypted executable (via csfix/modernized edition)
- [x] PE analysis: 6 sections, 461 imports, 19 DLLs
- [x] Identify compiler: MSVC 6.0 (linker 6.00, MFC42, MSVCRT, MSVCP60)
- [x] Identify engine: Zipper Interactive GameZ/GOS
- [x] Identify PDB path: D:\zipper\CrimsonRun\run\Crimson.pdb
- [x] Identify NB10 debug info (age 276)
- [x] Quick function estimate: ~5,865 functions, ~732K instructions
- [x] Document asset formats: ROF, ZBD, CAB, MPG, gosScript

### Phase 1: Disassembly & Function Discovery 🔄 IN PROGRESS

**Goal**: Map every function in the binary with address, size, and classification.

- [ ] Run full recursive-descent disassembly (pcrecomp disasm32)
- [ ] Generate functions.json with complete function map
- [ ] Cross-reference with IAT to identify import thunks
- [ ] Identify CRT functions (startup, heap, stdio, math, string)
- [ ] Identify MFC functions (via MFC42.DLL import ordinals)
- [ ] Identify GOS/GameOS engine functions (via string refs)
- [ ] Classify: game logic vs engine vs CRT vs MFC vs unknown
- [ ] Extract string references for function naming hints
- [ ] Load in Ghidra for interactive analysis alongside automated pipeline

**Key challenge**: 5,359 functions without standard prologues (frameless/optimized).
The pcrecomp classifier handles this using call graph + string ref + address
clustering heuristics, proven on Gunman Chronicles (3,990 functions, 78% auto-classified).

### Phase 2: Code Generation (Automated Lifting)

**Goal**: Convert all ~5,865 functions to compilable C code.

- [ ] Run pcrecomp lift32 on the decrypted binary
- [ ] Generate recomp_XXXX.c source files (expect ~800K-1M lines of C)
- [ ] Generate dispatch table (function address → C function mapping)
- [ ] Generate recomp_types.h (register model, memory macros)
- [ ] Apply known codegen fixes from XWA experience:
  - TEST reg,reg; jcc fix (signed/unsigned confusion)
  - DEC reg; jcc fix (compare vs 0 not 1)
  - repne scasb / repe cmpsb string operation fix
  - AND reg,imm; jcc fix
  - test reg; mov reg; jcc ordering fix
  - Block-scoped variable → function-scope fix

**Expected output**: ~35-40 MB of generated C code across 6-8 source files.

### Phase 3: Compilation & Linking

**Goal**: Get the generated code to compile with zero errors.

- [ ] Set up CMakeLists.txt for MSVC 2022 x86 build
- [ ] Resolve any remaining codegen errors
- [ ] Link against Win32 libraries
- [ ] Verify zero compile errors, document any warnings
- [ ] Binary size sanity check

### Phase 4: Runtime Bringup

**Goal**: Get the recompiled binary to execute through CRT init.

- [ ] Implement entry point and VEH crash handler
- [ ] Implement memory mapping (data sections at original VAs)
- [ ] Set up import bridge infrastructure
- [ ] Handle MSVC 6.0 CRT initialization quirks:
  - Small block heap (SBH) disable
  - Lock object pre-initialization
  - _initstdio manual implementation
  - Heap handle setup
- [ ] Implement Win32 API bridges (KERNEL32, USER32, GDI32)
- [ ] Verify CRT startup completes without crash

### Phase 5: DirectX COM Mocks

**Goal**: Get the game past DirectX initialization.

- [ ] Implement IDirectDraw mock (create surfaces, set cooperative level)
- [ ] Implement IDirectDrawSurface mock (Lock/Unlock/Blt/BltFast)
- [ ] Implement IDirect3D / IDirect3DDevice mock
- [ ] Implement IDirectInput / IDirectInputDevice mock
- [ ] Implement IDirectSound / IDirectSoundBuffer mock
- [ ] Implement IDirectPlay mock (for multiplayer init)
- [ ] Handle Immersion IFC21.dll force feedback (stub or mock)
- [ ] Implement ROFFILE.dll bridges (ROF archive access)
- [ ] Implement zTiff.dll bridges (TIFF loading → stb_image)

**Note**: XWA needed 178 COM vtable bridges + 179 Win32 API bridges.
Crimson Skies will need more due to MFC and additional middleware.

### Phase 6: GOS Engine Abstraction

**Goal**: Understand and document the GOS (Game Operating System) layer.

- [ ] Map GOS API functions (gos_LoadFont, gos_TextDraw, etc.)
- [ ] Identify GOS initialization sequence
- [ ] Document gosScript interpreter
- [ ] Map rendering pipeline: GOS → D3D Immediate Mode
- [ ] Map audio pipeline: GOS → DirectSound
- [ ] Map input pipeline: GOS → DirectInput

This is where the Crimson Skies / MechWarrior 3 engine knowledge really matters.
The mech3ax project has partial documentation of these structures.

### Phase 7: Asset Loading

**Goal**: Successfully load game assets from original data files.

- [ ] ROF archive reading (via ROFFILE.dll bridge or reimplementation)
- [ ] ZBD archive reading (format documented by mech3ax)
- [ ] CAB extraction for per-chapter data
- [ ] Texture loading (TGA, BMP, TIFF, JPEG)
- [ ] Sound loading from SOUNDSH.ZBD / SOUNDSL.ZBD
- [ ] Mission script loading from INTERP.ZBD
- [ ] MPEG-1 video playback for cutscenes

### Phase 8: Menu / UI Rendering

**Goal**: Render the game's menu system.

- [ ] Main menu rendering
- [ ] Campaign selection
- [ ] Plane customization screen
- [ ] Options screens
- [ ] Mission briefings

### Phase 9: Gameplay

**Goal**: Playable flight combat.

- [ ] Flight physics model
- [ ] Weapon systems
- [ ] AI opponents
- [ ] Mission scripting (gosScript)
- [ ] Campaign progression
- [ ] Multiplayer (DirectPlay → modern networking)

### Phase 10: Modern Rendering Backend

**Goal**: Replace D3D Immediate Mode with modern graphics.

- [ ] D3D11 or Vulkan backend
- [ ] Execute buffer → DrawPrimitive/DrawIndexed translation
- [ ] Modern shader pipeline
- [ ] Widescreen support (already partially solved by csfix)
- [ ] Higher resolution textures (upscaling pipeline)
- [ ] Modern post-processing (AA, HDR)

## Parallel Workstreams

These can happen alongside the main pipeline:

### Asset Documentation (anytime)
- Use mech3ax to extract and document all ZBD contents
- Map ROF archive structure
- Document gosScript format and opcodes
- Create asset viewer/browser

### Engine Cross-Reference (Phase 1+)
- Compare Crimson Skies binary patterns against MechWarrior 3
- The games share the GameZ/GOS engine — function signatures should match
- mech3ax's Rust code documents many shared structures

### Community Building (anytime)
- Document findings in the wiki
- Create development blog / progress videos
- Engage MechWarrior and flight sim communities
- Set up Discord for contributors

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| MFC complexity | High | MFC42.DLL is dynamically linked, so we bridge it rather than recompile it. Can stub unused MFC features. |
| gosScript interpreter | Medium | Complex interpreter but self-contained. Can trace execution to understand opcode behavior. |
| D3D Immediate Mode | Medium | XWA already solved this with execute buffer → D3D11 translation. Same approach applies. |
| Force feedback (IFC21) | Low | Can be completely stubbed — just a joystick rumble library |
| Encrypted jump tables | Medium | SafeDisc may have encrypted some switch/case tables. XWA had 6 of these. Pattern is documented. |
| Code size (2x XWA) | Medium | More functions = more time, but the pipeline is fully automated. Human effort is in the runtime, not the lifting. |

## Key Insight from XWA

The hardest part isn't code generation — it's runtime bringup. The lifter produces
compilable C mechanically. The real work is:

1. **CRT initialization**: MSVC 6.0 CRT has quirks that break with modern CRT
2. **COM mocking**: Every DirectX interface needs a mock with correct vtable layout
3. **Codegen edge cases**: ~30 pattern fixes were needed for XWA, all fed back into the lifter
4. **Data format understanding**: File I/O, string tables, config parsing

The good news: all 30 XWA codegen fixes are already in the pcrecomp lifter. Crimson
Skies should need far fewer manual corrections.

## Timeline Estimate

Not giving one. This is a preservation project, not a sprint. But for reference:
- XWA Phase 0-3 (analysis → compilable code): ~1 week
- XWA Phase 4-7 (runtime → concourse rendering): ~3 weeks
- XWA Phase 8+ (gameplay): ongoing

Crimson Skies is ~2x the code size, but we have better tools now.
