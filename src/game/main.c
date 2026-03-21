/**
 * Crimson Skies Static Recompilation — Entry Point
 *
 * Phase 4: Runtime bringup
 * - Memory mapping: .rdata, .data, .idata, .rsrc at original VAs
 * - Simulated stack at a fixed low address
 * - SEH workaround: page at VA 0 for fs:[0] codegen bug
 * - Import bridge setup: populate IAT with sentinel → bridge dispatch
 * - Entry point call to recompiled WinMain (0x005F7056)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../recomp/recomp_types.h"
#include "recomp_funcs.h"

/*========================================================================
 * Global Register State
 *========================================================================*/

uint32_t g_eax = 0, g_ecx = 0, g_edx = 0, g_esp = 0;
uint32_t g_ebx = 0, g_esi = 0, g_edi = 0;
uint16_t g_seg_cs = 0, g_seg_ds = 0, g_seg_es = 0;
uint16_t g_seg_fs = 0, g_seg_gs = 0, g_seg_ss = 0;
ptrdiff_t g_mem_base = 0;
uint32_t g_fs_seg[256] = {0};

/* Dispatch/trace infrastructure */
uint32_t g_icall_trace[ICALL_TRACE_SIZE] = {0};
uint32_t g_icall_trace_idx = 0;
uint32_t g_icall_count = 0;
uint32_t g_call_depth = 0;
uint32_t g_call_depth_max = 0;
uint32_t g_total_calls = 0;
uint32_t g_total_icalls = 0;
int g_heap_check_enabled = 0;
uint32_t g_heap_check_last_ok_call = 0;
uint32_t g_heap_check_last_ok_va = 0;
char g_trace_ring[TRACE_RING_SIZE][TRACE_ENTRY_SIZE];
uint32_t g_trace_ring_idx = 0;

/*========================================================================
 * Memory Layout (from PE analysis of CRIMSON_decrypted.exe)
 *
 * .text:  0x00401000  VSize=0x2014BD  (code — WE are the code)
 * .rdata: 0x00603000  VSize=0x159A0   (read-only data)
 * .data:  0x00619000  VSize=0x4051D4  (read/write data, 4MB virtual)
 * .idata: 0x00A1F000  VSize=0x362D    (import address table)
 * .rsrc:  0x00A23000  VSize=0x591E    (resources)
 *
 * Raw file offsets (for loading initialized data):
 * .rdata: raw_offset=0x203000  raw_size=0x16000
 * .data:  raw_offset=0x219000  raw_size=0x2A000
 * .idata: raw_offset=0x243000  raw_size=0x4000
 * .rsrc:  raw_offset=0x247000  raw_size=0x6000
 *========================================================================*/

#define CS_IMAGE_BASE   0x00400000

/*
 * With the exe rebased to 0x10000000, the original VA range
 * (0x00000000 - 0x00A29000) is free. We map data sections at
 * their original VAs and use g_mem_base = 0. This means all
 * addresses are real — no translation needed. MEM32(ptr) = *(ptr).
 * Heap allocations (malloc, new) return real addresses that work
 * directly with MEM32().
 */
#define CS_DATA_START      0x00603000  /* .rdata VA */
#define CS_DATA_END        0x00A29000  /* .rsrc end, rounded up */
#define CS_DATA_SIZE       (CS_DATA_END - CS_DATA_START)

/* Stack: 1MB at 0x00100000 */
#define CS_STACK_SIZE   0x00100000  /* 1 MB */

/* PE file section offsets for loading initialized data */
typedef struct {
    uint32_t va;
    uint32_t raw_offset;
    uint32_t raw_size;
} section_load_t;

static const section_load_t g_sections_to_load[] = {
    { 0x00603000, 0x203000, 0x16000 },  /* .rdata */
    { 0x00619000, 0x219000, 0x2A000 },  /* .data  */
    { 0x00A1F000, 0x243000, 0x4000  },  /* .idata */
    { 0x00A23000, 0x247000, 0x6000  },  /* .rsrc  */
};
#define NUM_SECTIONS_TO_LOAD (sizeof(g_sections_to_load)/sizeof(g_sections_to_load[0]))

/* Memory allocations tracked for cleanup */

/*========================================================================
 * Import Bridge Infrastructure
 *
 * Strategy: Each IAT slot gets a unique sentinel value (0xFE000000 + index).
 * When RECOMP_ICALL reads an IAT slot and tries to dispatch, it hits
 * recomp_lookup_import() which maps sentinel → bridge function.
 *
 * Bridge functions read args from the recomp stack (g_esp), call the
 * real Win32/CRT function, put the result in g_eax, and adjust g_esp
 * for stdcall (callee-cleans) or leave it for cdecl (caller-cleans).
 *========================================================================*/

#define IMPORT_SENTINEL_BASE  0xFE000000u
#define MAX_IMPORT_BRIDGES    700

typedef struct {
    uint32_t sentinel;       /* sentinel value in IAT slot */
    uint32_t iat_va;         /* original IAT virtual address */
    recomp_func_t bridge;    /* bridge function (or NULL for native passthrough) */
    void* native_addr;       /* real DLL function address */
    const char* dll_name;
    const char* func_name;
    int nargs;               /* number of 32-bit stack args (-1 = unknown) */
    int is_stdcall;          /* 1 = stdcall (callee cleans), 0 = cdecl, 2 = thiscall */
} import_entry_t;

static import_entry_t g_imports[MAX_IMPORT_BRIDGES];
static int g_import_count = 0;

/* Stack access helpers for bridge functions */
#define STACK32(n) MEM32(g_esp + 4 + (n)*4)  /* +4 to skip return address */

/*------------------------------------------------------------------------
 * Generic bridge: reads N args from recomp stack, calls native function
 * via a universal stdcall/cdecl thunk.
 *------------------------------------------------------------------------*/

/* Forward declaration */
static void thiscall_bridge(int idx);

/* Generic bridge dispatcher — called from per-import thunks */
static void generic_bridge(int idx) {
    import_entry_t* imp = &g_imports[idx];
    void* fn = imp->native_addr;
    int nargs = imp->nargs;

    if (!fn) {
        fprintf(stderr, "BRIDGE: NULL native for %s!%s\n", imp->dll_name, imp->func_name);
        g_eax = 0;
        return;
    }

    /* Read args from recomp stack */
    uint32_t a[16];
    for (int i = 0; i < nargs && i < 16; i++) {
        a[i] = STACK32(i);
    }

    /* Call native function.
     * All Win32 APIs are __stdcall (callee-cleans).
     * MSVCRT functions are __cdecl (caller-cleans).
     * We use inline asm or a function pointer cast to make the call. */

    uint32_t result = 0;

    /* Use a switch on nargs for the call — the compiler will optimize this */
    typedef uint32_t (__stdcall *fn0_t)(void);
    typedef uint32_t (__stdcall *fn1_t)(uint32_t);
    typedef uint32_t (__stdcall *fn2_t)(uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn3_t)(uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn5_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn6_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn7_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn8_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn9_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn10_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn11_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *fn12_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

    typedef uint32_t (__cdecl *cfn0_t)(void);
    typedef uint32_t (__cdecl *cfn1_t)(uint32_t);
    typedef uint32_t (__cdecl *cfn2_t)(uint32_t, uint32_t);
    typedef uint32_t (__cdecl *cfn3_t)(uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__cdecl *cfn4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__cdecl *cfn5_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__cdecl *cfn6_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__cdecl *cfn7_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__cdecl *cfn8_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

    if (imp->is_stdcall == 2) {
        /* thiscall — delegate to thiscall_bridge */
        thiscall_bridge(idx);
        return;
    }

    if (imp->is_stdcall) {
        switch (nargs) {
            case 0:  result = ((fn0_t)fn)(); break;
            case 1:  result = ((fn1_t)fn)(a[0]); break;
            case 2:  result = ((fn2_t)fn)(a[0], a[1]); break;
            case 3:  result = ((fn3_t)fn)(a[0], a[1], a[2]); break;
            case 4:  result = ((fn4_t)fn)(a[0], a[1], a[2], a[3]); break;
            case 5:  result = ((fn5_t)fn)(a[0], a[1], a[2], a[3], a[4]); break;
            case 6:  result = ((fn6_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5]); break;
            case 7:  result = ((fn7_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]); break;
            case 8:  result = ((fn8_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); break;
            case 9:  result = ((fn9_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]); break;
            case 10: result = ((fn10_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]); break;
            case 11: result = ((fn11_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]); break;
            case 12: result = ((fn12_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11]); break;
            default:
                fprintf(stderr, "BRIDGE: unsupported nargs=%d for %s!%s\n", nargs, imp->dll_name, imp->func_name);
                break;
        }
        /* stdcall: callee cleans stack */
        g_esp += nargs * 4;
    } else {
        /* cdecl: caller cleans stack — we don't touch g_esp */
        switch (nargs) {
            case 0:  result = ((cfn0_t)fn)(); break;
            case 1:  result = ((cfn1_t)fn)(a[0]); break;
            case 2:  result = ((cfn2_t)fn)(a[0], a[1]); break;
            case 3:  result = ((cfn3_t)fn)(a[0], a[1], a[2]); break;
            case 4:  result = ((cfn4_t)fn)(a[0], a[1], a[2], a[3]); break;
            case 5:  result = ((cfn5_t)fn)(a[0], a[1], a[2], a[3], a[4]); break;
            case 6:  result = ((cfn6_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5]); break;
            case 7:  result = ((cfn7_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]); break;
            case 8:  result = ((cfn8_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); break;
            default:
                fprintf(stderr, "BRIDGE: unsupported nargs=%d for %s!%s\n", nargs, imp->dll_name, imp->func_name);
                break;
        }
    }

    g_eax = result;
}

/*------------------------------------------------------------------------
 * Thiscall bridge for MFC42 and similar C++ DLLs.
 *
 * __thiscall: ECX = this, callee-cleans stack args.
 * We don't know exact arg counts, so we copy a generous 12 dwords
 * from the recomp stack onto the native stack, call the function,
 * and detect how many args were consumed by checking ESP delta.
 *------------------------------------------------------------------------*/

/*
 * Thiscall trampoline: calls a __thiscall function with ECX = this.
 * Since C doesn't support __thiscall function pointers, we use
 * __stdcall casts and set ECX manually via inline asm.
 * Note: __stdcall = callee-cleans, same as __thiscall but with
 * ECX set manually rather than first arg.
 */

static void thiscall_bridge(int idx) {
    import_entry_t* imp = &g_imports[idx];
    void* fn = imp->native_addr;

    if (!fn) {
        static int null_warn_count = 0;
        if (null_warn_count < 5) {
            fprintf(stderr, "BRIDGE: NULL native for %s!%s (thiscall)\n",
                    imp->dll_name, imp->func_name);
            null_warn_count++;
        }
        g_eax = 0;
        return;
    }

    uint32_t a[12];
    int nargs = imp->nargs;
    for (int i = 0; i < nargs && i < 12; i++) {
        a[i] = STACK32(i);
    }

    /* Use stdcall function pointer types (same stack cleanup as thiscall) */
    typedef uint32_t (__stdcall *tc0_t)(void);
    typedef uint32_t (__stdcall *tc1_t)(uint32_t);
    typedef uint32_t (__stdcall *tc2_t)(uint32_t, uint32_t);
    typedef uint32_t (__stdcall *tc3_t)(uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *tc4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *tc5_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *tc6_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *tc7_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (__stdcall *tc8_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

    /* Set ECX = this (g_ecx) before the call via inline asm.
     * MFC objects are heap-allocated with real addresses from malloc. */
    uint32_t this_ecx = g_ecx;
    uint32_t result = 0;

    /* The __asm mov ecx right before the switch works because MSVC
     * won't touch ECX between our asm and the call (it's caller-saved
     * and the compiler knows we set it). */
    __asm { mov ecx, this_ecx }
    switch (nargs) {
        case 0:  result = ((tc0_t)fn)(); break;
        case 1:  result = ((tc1_t)fn)(a[0]); break;
        case 2:  result = ((tc2_t)fn)(a[0], a[1]); break;
        case 3:  result = ((tc3_t)fn)(a[0], a[1], a[2]); break;
        case 4:  result = ((tc4_t)fn)(a[0], a[1], a[2], a[3]); break;
        case 5:  result = ((tc5_t)fn)(a[0], a[1], a[2], a[3], a[4]); break;
        case 6:  result = ((tc6_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5]); break;
        case 7:  result = ((tc7_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]); break;
        case 8:  result = ((tc8_t)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); break;
        default:
            fprintf(stderr, "BRIDGE: thiscall unsupported nargs=%d for %s!%s\n",
                    nargs, imp->dll_name, imp->func_name);
            break;
    }

    /* thiscall: callee cleans stack args */
    g_esp += nargs * 4;
    g_eax = result;
}

/*------------------------------------------------------------------------
 * Import registration
 *------------------------------------------------------------------------*/

static int register_import(uint32_t iat_va, const char* dll_name,
                           const char* func_name, void* native_addr,
                           int nargs, int is_stdcall, recomp_func_t bridge) {
    if (g_import_count >= MAX_IMPORT_BRIDGES) {
        fprintf(stderr, "ERROR: import bridge table full\n");
        return 0;
    }

    int idx = g_import_count;
    uint32_t sentinel = IMPORT_SENTINEL_BASE + idx;

    g_imports[idx].sentinel = sentinel;
    g_imports[idx].iat_va = iat_va;
    g_imports[idx].bridge = bridge;
    g_imports[idx].native_addr = native_addr;
    g_imports[idx].dll_name = dll_name;
    g_imports[idx].func_name = func_name;
    g_imports[idx].nargs = nargs;
    g_imports[idx].is_stdcall = is_stdcall;

    /* Write sentinel value into the IAT slot */
    MEM32(iat_va) = sentinel;

    g_import_count++;
    return 1;
}

/* Track which IAT slots have been handled as data imports */
#define MAX_DATA_IMPORTS_DECL 64
static uint32_t g_data_import_vas_arr[MAX_DATA_IMPORTS_DECL];
static int g_data_import_count_val = 0;

/* Check if an IAT slot already has a registered bridge or data import */
static int is_iat_registered(uint32_t iat_va) {
    for (int i = 0; i < g_import_count; i++) {
        if (g_imports[i].iat_va == iat_va) return 1;
    }
    for (int i = 0; i < g_data_import_count_val; i++) {
        if (g_data_import_vas_arr[i] == iat_va) return 1;
    }
    return 0;
}

/* Helper: register an import resolved by GetProcAddress */
static int register_import_auto(uint32_t iat_va, const char* dll_name,
                                const char* func_name, int nargs, int is_stdcall) {
    /* Skip if this IAT slot already has a custom bridge or data import */
    if (is_iat_registered(iat_va)) return 1;
    HMODULE hmod = LoadLibraryA(dll_name);
    if (!hmod) {
        fprintf(stderr, "WARNING: Could not load %s\n", dll_name);
        return register_import(iat_va, dll_name, func_name, NULL, nargs, is_stdcall, NULL);
    }

    void* addr = (void*)GetProcAddress(hmod, func_name);
    if (!addr) {
        fprintf(stderr, "WARNING: %s!%s not found\n", dll_name, func_name);
    }

    return register_import(iat_va, dll_name, func_name, addr, nargs, is_stdcall, NULL);
}

/* Helper: write a data import value directly into the IAT slot.
 * For imports like _adjust_fdiv, _iob, _pctype, _HUGE, _acmdln, __mb_cur_max
 * where the IAT slot holds a pointer to data (not a function to call). */
static void register_data_import(uint32_t iat_va, uint32_t value) {
    MEM32(iat_va) = value;
    if (g_data_import_count_val < MAX_DATA_IMPORTS_DECL) {
        g_data_import_vas_arr[g_data_import_count_val++] = iat_va;
    }
}

/* Helper: register ordinal import */
static int register_import_ordinal(uint32_t iat_va, const char* dll_name,
                                   int ordinal, int nargs, int is_stdcall) {
    if (is_iat_registered(iat_va)) return 1;
    HMODULE hmod = LoadLibraryA(dll_name);
    if (!hmod) {
        fprintf(stderr, "WARNING: Could not load %s\n", dll_name);
        return register_import(iat_va, dll_name, "ordinal", NULL, nargs, is_stdcall, NULL);
    }

    void* addr = (void*)GetProcAddress(hmod, MAKEINTRESOURCEA(ordinal));
    char name_buf[32];
    snprintf(name_buf, sizeof(name_buf), "ordinal_%d", ordinal);

    return register_import(iat_va, dll_name, name_buf, addr, nargs, is_stdcall, NULL);
}

/*------------------------------------------------------------------------
 * Import bridge lookup (called from RECOMP_ICALL)
 *------------------------------------------------------------------------*/

recomp_func_t recomp_lookup_import(uint32_t va) {
    /* Check if this is one of our sentinel values */
    if (va >= IMPORT_SENTINEL_BASE && va < IMPORT_SENTINEL_BASE + (uint32_t)g_import_count) {
        int idx = (int)(va - IMPORT_SENTINEL_BASE);
        if (g_imports[idx].bridge) {
            return g_imports[idx].bridge;
        }
        /* No custom bridge — use generic bridge */
        /* We can't return a function pointer to generic_bridge(idx) directly,
         * so we use recomp_native_call instead */
        return NULL;
    }
    return NULL;
}

int recomp_native_call(uint32_t va) {
    /* Check if this is one of our sentinel values */
    if (va >= IMPORT_SENTINEL_BASE && va < IMPORT_SENTINEL_BASE + (uint32_t)g_import_count) {
        int idx = (int)(va - IMPORT_SENTINEL_BASE);
        generic_bridge(idx);
        return 1;
    }
    return 0;
}

/*========================================================================
 * Dispatch Infrastructure
 *========================================================================*/

recomp_func_t recomp_lookup(uint32_t va) {
    int lo = 0, hi = (int)recomp_dispatch_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint32_t addr = recomp_dispatch_table[mid].address;
        if (addr == va) return recomp_dispatch_table[mid].func;
        if (addr < va) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}

/*========================================================================
 * Manual Override Functions
 *
 * Functions the code generator missed. Hand-translated from disassembly.
 *========================================================================*/

/*========================================================================
 * Stub Functions (bogus/missing call targets)
 *========================================================================*/

/* sub_EFE6F9FA: bogus call target (data misinterpreted as code) */
void sub_EFE6F9FA(void) {
    STUB("sub_EFE6F9FA (bogus address)");
}

/* sub_005CB0B0: missing function — address not in discovered function list */
void sub_005CB0B0(void) {
    STUB("sub_005CB0B0");
    g_eax = 0;
}

/*========================================================================
 * Manual Override Functions
 *========================================================================*/

/* 0x005FC551: CRT _cinit — calls sub_005FC528 to init CRT subsystems */
static void manual_005FC551(void) {
    uint32_t ebp = 0;
    /* jmp +0 (nop), push 0x600, push 0, call sub_005FC528 */
    PUSH32(g_esp, 0);
    PUSH32(g_esp, 0x600u);
    PUSH32(g_esp, 0xDEAD0000u);
    sub_005FC528();
    /* mov byte ptr [0x9FAC74], al */
    MEM8(0x9FAC74) = (uint8_t)(g_eax & 0xFF);
}

/* 0x00411B10: thiscall constructor — sets vtable pointer */
static void manual_00411B10(void) {
    /* mov eax, ecx; mov [eax], 0x603320; mov [eax+4], 0; ret */
    g_eax = g_ecx;
    MEM32(g_eax) = 0x00603320u;
    MEM32(g_eax + 4) = 0;
}

/* 0x00411C90: thiscall constructor — zeroes object */
static void manual_00411C90(void) {
    g_eax = g_ecx;
    MEM32(g_eax) = 0;
    MEM32(g_eax + 4) = 0;
}

/* 0x0045E280: thiscall constructor — init byte + 3 dwords */
static void manual_0045E280(void) {
    /* push ecx; mov eax, ecx; mov cl, [esp+3]; mov [eax], cl;
     * xor ecx, ecx; mov [eax+4/8/C], ecx; pop ecx; ret */
    uint32_t saved_ecx = g_ecx;
    g_eax = g_ecx;
    /* [esp+3] after push ecx = the low byte of the dword at original esp+0
     * This is the first arg byte passed via register (thiscall quirk).
     * Actually [esp+3] after push ecx is byte 3 of the return address.
     * This is a VC6 optimization — the "arg" was in the high byte of the
     * pushed value. For init purposes, just zero everything. */
    MEM8(g_eax) = 0;
    MEM32(g_eax + 4) = 0;
    MEM32(g_eax + 8) = 0;
    MEM32(g_eax + 0xC) = 0;
    g_ecx = saved_ecx;
}

/* 0x00410560: thiscall constructor — init fields at +0x24, +0x28, +0x2C, +0x30 */
static void manual_00410560(void) {
    g_eax = g_ecx;
    MEM32(g_eax + 0x24) = 0x22;
    MEM32(g_eax + 0x28) = 5;
    MEM8(g_eax + 0x2C) = 0;
    MEM32(g_eax + 0x30) = 0;
}

/* 0x00410D90: thiscall constructor — calls sub_005F6F5A (array init), sets fields */
static void manual_00410D90(void) {
    uint32_t saved_esi = g_esi;
    g_esi = g_ecx;
    PUSH32(g_esp, g_esi);
    PUSH32(g_esp, 0x10u);
    PUSH32(g_esp, 0x64u);
    PUSH32(g_esp, 0x00411010u);
    PUSH32(g_esp, 0x00411140u);
    PUSH32(g_esp, 0xDEAD0000u);
    {
        recomp_func_t fn = recomp_lookup(0x005F6F5A);
        if (fn) fn();
    }
    MEM32(g_esi + 0x648) = 0;
    MEM32(g_esi + 0x640) = 0;
    MEM32(g_esi + 0x644) = 0x64;
    g_eax = g_esi;
    g_esi = saved_esi;
}

/* 0x004DE740: thiscall constructor — alloc node, init linked list */
static void manual_004DE740(void) {
    uint32_t saved_esi = g_esi;
    g_esi = g_ecx;
    /* mov al, [esp+3] after push ecx — quirky arg passing, use 0 */
    MEM8(g_esi) = 0;
    /* call sub_005F6976 (malloc wrapper) with arg 0xC */
    PUSH32(g_esp, 0xCu);
    PUSH32(g_esp, 0xDEAD0000u);
    {
        recomp_func_t fn = recomp_lookup(0x005F6976);
        if (fn) fn();
    }
    g_esp += 4; /* cdecl: caller clean 1 arg */
    /* eax = allocated node; set node->next = node->prev = node (self-referencing) */
    MEM32(g_eax) = g_eax;
    MEM32(g_eax + 4) = g_eax;
    MEM32(g_esi + 4) = g_eax;
    MEM32(g_esi + 8) = 0;
    g_eax = g_esi;
    g_esi = saved_esi;
}

/* Manual override table */
static recomp_dispatch_entry_t g_manual_overrides[] = {
    { 0x005FC551u, manual_005FC551 },
    { 0x00411B10u, manual_00411B10 },
    { 0x00411C90u, manual_00411C90 },
    { 0x0045E280u, manual_0045E280 },
    { 0x00410560u, manual_00410560 },
    { 0x00410D90u, manual_00410D90 },
    { 0x004DE740u, manual_004DE740 },
    { 0, NULL }  /* sentinel */
};
static const int g_manual_override_count = 7;

recomp_func_t recomp_lookup_manual(uint32_t va) {
    for (int i = 0; i < g_manual_override_count; i++) {
        if (g_manual_overrides[i].address == va)
            return g_manual_overrides[i].func;
    }
    return NULL;
}

void recomp_register_native(uint32_t addr, const char* name, int nargs) {
    (void)addr; (void)name; (void)nargs;
}

/*========================================================================
 * Special Bridge Functions
 *
 * Some imports need custom handling because they return pointers to
 * data (not just uint32_t), have varargs, or need special treatment.
 *========================================================================*/

/* _except_handler3: VC6 SEH handler — stub it out */
static void bridge_except_handler3(void) {
    /* SEH dispatch — for now, just return EXCEPTION_CONTINUE_SEARCH */
    g_eax = 1; /* ExceptionContinueSearch */
    g_esp += 16; /* stdcall, 4 args */
}

/* __CxxFrameHandler: C++ exception handler — stub */
static void bridge_CxxFrameHandler(void) {
    g_eax = 1;
    g_esp += 16;
}

/* _purecall: pure virtual call handler */
static void bridge_purecall(void) {
    fprintf(stderr, "FATAL: Pure virtual function call!\n");
    g_eax = 0;
}

/* __set_app_type: CRT init — ignore */
static void bridge_set_app_type(void) {
    /* arg: int type (on stack) */
    g_esp += 4; /* cdecl but original code pops it */
    g_eax = 0;
}

/* __p__fmode: returns pointer to _fmode variable */
static void bridge_p_fmode(void) {
    static uint32_t fmode_va = 0;
    if (!fmode_va) {
        fmode_va = 0x00A1E000; /* scratch area in mapped region */
        MEM32(fmode_va) = 0;   /* _O_TEXT */
    }
    g_eax = fmode_va;
}

/* __p__commode: returns pointer to _commode variable */
static void bridge_p_commode(void) {
    static uint32_t commode_va = 0;
    if (!commode_va) {
        commode_va = 0x00A1E004;
        MEM32(commode_va) = 0;
    }
    g_eax = commode_va;
}

/* _initterm: calls an array of function pointers (CRT init) */
static void bridge_initterm(void) {
    uint32_t start = STACK32(0);  /* pointer to start of array */
    uint32_t end = STACK32(1);    /* pointer to end of array */

    printf("[*] _initterm: 0x%08X - 0x%08X\n", start, end);

    uint32_t ptr = start;
    int called = 0, skipped = 0;
    while (ptr < end) {
        uint32_t fn_va = MEM32(ptr);
        if (fn_va != 0) {
            /* Try all lookup methods: manual overrides, dispatch table */
            recomp_func_t fn = recomp_lookup_manual(fn_va);
            if (!fn) fn = recomp_lookup(fn_va);
            if (!fn) {
                /* VC6 CRT init thunks: the real constructor is at fn_va + 0x10.
                 * Pattern: call +0x10; jmp <atexit_register>; nop padding
                 * We skip the atexit registration and just call the constructor. */
                fn = recomp_lookup_manual(fn_va + 0x10);
                if (!fn) fn = recomp_lookup(fn_va + 0x10);
            }
            if (fn) {
                uint32_t save_esp = g_esp;
                PUSH32(g_esp, 0xDEAD0000u);
                fn();
                g_esp = save_esp; /* restore ESP in case of stack imbalance */
                called++;
            } else {
                fprintf(stderr, "    WARNING: init func 0x%08X not found (tried +0x10 too)\n", fn_va);
                skipped++;
            }
        }
        ptr += 4;
    }

    printf("    _initterm: called %d, skipped %d\n", called, skipped);
    g_eax = 0;
}

/* __getmainargs: CRT startup — populate argc/argv */
static void bridge_getmainargs(void) {
    uint32_t p_argc = STACK32(0);
    uint32_t p_argv = STACK32(1);
    uint32_t p_envp = STACK32(2);
    /* uint32_t do_wildcards = STACK32(3); */

    /* Provide minimal argc/argv */
    MEM32(p_argc) = 1;

    /* We need to put argv[0] string and pointer somewhere in mapped memory */
    /* Use a scratch area */
    uint32_t scratch = 0x00A1E010;
    const char* exe_name = "CRIMSON.EXE";
    memcpy((void*)ADDR(scratch), exe_name, strlen(exe_name) + 1);

    /* argv array: argv[0] = pointer to exe_name, argv[1] = NULL */
    uint32_t argv_base = scratch + 64;
    MEM32(argv_base) = scratch;
    MEM32(argv_base + 4) = 0;
    MEM32(p_argv) = argv_base;

    /* envp: empty */
    uint32_t envp_base = argv_base + 16;
    MEM32(envp_base) = 0;
    MEM32(p_envp) = envp_base;

    g_eax = 0;
}

/* __setusermatherr: set math error handler — ignore */
static void bridge_setusermatherr(void) {
    g_eax = 0;
}

/* _XcptFilter: exception filter — return EXCEPTION_CONTINUE_SEARCH */
static void bridge_XcptFilter(void) {
    g_eax = 0; /* EXCEPTION_CONTINUE_SEARCH */
}

/* _acmdln: returns pointer to command line string */
static void bridge_acmdln(void) {
    static uint32_t cmdln_va = 0;
    if (!cmdln_va) {
        cmdln_va = 0x00A1E080;
        const char* cmd = "CRIMSON.EXE";
        memcpy((void*)ADDR(cmdln_va), cmd, strlen(cmd) + 1);
    }
    /* _acmdln is a data import — its IAT slot should point to the pointer */
    g_eax = cmdln_va;
}

/* _iob: returns pointer to stdio file table */
static void bridge_iob(void) {
    /* Return address of real _iob from MSVCRT */
    HMODULE hcrt = GetModuleHandleA("MSVCRT.dll");
    if (hcrt) {
        void* iob = (void*)GetProcAddress(hcrt, "_iob");
        g_eax = (uint32_t)(uintptr_t)iob;
    } else {
        g_eax = 0;
    }
}

/* _pctype: returns pointer to ctype table */
static void bridge_pctype(void) {
    HMODULE hcrt = GetModuleHandleA("MSVCRT.dll");
    if (hcrt) {
        void* p = (void*)GetProcAddress(hcrt, "_pctype");
        g_eax = (uint32_t)(uintptr_t)p;
    } else {
        g_eax = 0;
    }
}

/* __mb_cur_max: multibyte max length */
static void bridge_mb_cur_max(void) {
    HMODULE hcrt = GetModuleHandleA("MSVCRT.dll");
    if (hcrt) {
        void* p = (void*)GetProcAddress(hcrt, "__mb_cur_max");
        g_eax = (uint32_t)(uintptr_t)p;
    } else {
        g_eax = 0;
    }
}

/* _HUGE: pointer to HUGE_VAL */
static void bridge_HUGE(void) {
    HMODULE hcrt = GetModuleHandleA("MSVCRT.dll");
    if (hcrt) {
        void* p = (void*)GetProcAddress(hcrt, "_HUGE");
        g_eax = (uint32_t)(uintptr_t)p;
    } else {
        g_eax = 0;
    }
}

/* GetStartupInfoA: pointer arg needs VA->real conversion */
static void bridge_GetStartupInfoA(void) {
    uint32_t va = STACK32(0);
    GetStartupInfoA((LPSTARTUPINFOA)ADDR(va));
    g_esp += 4; /* stdcall, 1 arg */
    g_eax = 0;
}

/* GetModuleHandleA: string pointer arg */
static void bridge_GetModuleHandleA(void) {
    uint32_t va = STACK32(0);
    LPCSTR name = va ? (LPCSTR)ADDR(va) : NULL;
    g_eax = (uint32_t)(uintptr_t)GetModuleHandleA(name);
    g_esp += 4;
}

/* GetModuleFileNameA: buffer pointer arg */
static void bridge_GetModuleFileNameA(void) {
    uint32_t hModule = STACK32(0);
    uint32_t buf_va = STACK32(1);
    uint32_t nSize = STACK32(2);
    g_eax = GetModuleFileNameA((HMODULE)(uintptr_t)hModule, (LPSTR)ADDR(buf_va), nSize);
    g_esp += 12;
}

/* GetCommandLineA: returns real pointer — no VA needed */
static void bridge_GetCommandLineA(void) {
    g_eax = (uint32_t)(uintptr_t)GetCommandLineA();
    g_esp += 0; /* stdcall, 0 args */
}

/* _errno: returns pointer to errno */
static void bridge_errno(void) {
    HMODULE hcrt = GetModuleHandleA("MSVCRT.dll");
    if (hcrt) {
        typedef int* (__cdecl *errno_fn)(void);
        errno_fn fn = (errno_fn)GetProcAddress(hcrt, "_errno");
        if (fn) {
            g_eax = (uint32_t)(uintptr_t)fn();
            return;
        }
    }
    static int fake_errno = 0;
    g_eax = (uint32_t)(uintptr_t)&fake_errno;
}

/*========================================================================
 * Heap Management — malloc/free/calloc/realloc bridges
 *
 * Allocations must return VAs (not real addresses) so that MEM32(ptr)
 * works correctly with the g_mem_base offset. We use a Win32 HeapCreate
 * at a real address within our VA block, and return VA = real - g_mem_base.
 *========================================================================*/

static HANDLE g_recomp_heap = NULL;

static void init_recomp_heap(void) {
    /* Create a private heap within our VA range.
     * The heap will allocate at real addresses within
     * [ADDR(CS_HEAP_VA_START), ADDR(CS_HEAP_VA_END)].
     * We use VirtualAlloc to reserve this range first. */
    g_recomp_heap = HeapCreate(0, 0x100000, 0); /* growable, 1MB initial */
    if (!g_recomp_heap) {
        fprintf(stderr, "FATAL: HeapCreate failed for recomp heap\n");
    }
}

/* Convert real heap address to VA */
static uint32_t heap_real_to_va(void* real) {
    return (uint32_t)((uintptr_t)real - g_mem_base);
}

/* Convert VA back to real address */
static void* heap_va_to_real(uint32_t va) {
    return (void*)ADDR(va);
}

/* malloc bridge: returns VA */
static void bridge_malloc(void) {
    uint32_t size = STACK32(0);
    void* ptr = HeapAlloc(g_recomp_heap, 0, size);
    g_eax = ptr ? heap_real_to_va(ptr) : 0;
}

/* free bridge: takes VA */
static void bridge_free(void) {
    uint32_t va = STACK32(0);
    if (va) {
        HeapFree(g_recomp_heap, 0, heap_va_to_real(va));
    }
    g_eax = 0;
}

/* calloc bridge: returns VA */
static void bridge_calloc(void) {
    uint32_t count = STACK32(0);
    uint32_t size = STACK32(1);
    void* ptr = HeapAlloc(g_recomp_heap, HEAP_ZERO_MEMORY, count * size);
    g_eax = ptr ? heap_real_to_va(ptr) : 0;
}

/* realloc bridge: takes VA, returns VA */
static void bridge_realloc(void) {
    uint32_t va = STACK32(0);
    uint32_t size = STACK32(1);
    void* ptr;
    if (va == 0) {
        ptr = HeapAlloc(g_recomp_heap, 0, size);
    } else if (size == 0) {
        HeapFree(g_recomp_heap, 0, heap_va_to_real(va));
        ptr = NULL;
    } else {
        ptr = HeapReAlloc(g_recomp_heap, 0, heap_va_to_real(va), size);
    }
    g_eax = ptr ? heap_real_to_va(ptr) : 0;
}

/* _strdup bridge: allocates copy, returns VA */
static void bridge_strdup(void) {
    uint32_t str_va = STACK32(0);
    const char* src = (const char*)ADDR(str_va);
    size_t len = strlen(src) + 1;
    void* dst = HeapAlloc(g_recomp_heap, 0, len);
    if (dst) {
        memcpy(dst, src, len);
        g_eax = heap_real_to_va(dst);
    } else {
        g_eax = 0;
    }
}

/* operator new (called via _purecall path or directly) */
/* Note: The C++ new operator in MSVCRT just calls malloc */

/*========================================================================
 * VEH Crash Handler
 *========================================================================*/

/*
 * SEH simulation area — used when code accesses VA 0 (fs:[0]).
 * With g_mem_base=0, MEM32(0) tries to access real address 0 which
 * crashes. We catch the AV in VEH and simulate the access using
 * this buffer. The SEH chain head at fs:[0] is typically 0xFFFFFFFF
 * (end of chain) or a pointer to the current SEH frame.
 */
static uint32_t g_seh_sim[16] = { 0xFFFFFFFF };

static LONG WINAPI veh_handler(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PVOID addr = ep->ExceptionRecord->ExceptionAddress;

    /* Handle access violations at null page (fs:[0] workaround) */
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        uintptr_t fault_addr = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
        if (fault_addr < 0x10000) {
            /* Access to null page — redirect to g_seh_sim.
             * This handles the fs:[0] codegen bug where MEM32(0) is used
             * instead of FS_MEM32(0). */
            /* For reads: put result in the register the instruction was loading to.
             * For writes: discard the value.
             * Simplest: skip the instruction. But we don't know instruction length.
             * Alternative: just return the SEH chain end value. */

            /* We can't easily fix the instruction pointer here.
             * Instead, temporarily map a page at VA 0 using a different approach. */
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    /* Skip first-chance C++ exceptions */
    if (code == 0xE06D7363) return EXCEPTION_CONTINUE_SEARCH;

    fprintf(stderr, "\n=== CRIMSON SKIES RECOMP CRASH ===\n");
    fprintf(stderr, "Exception 0x%08X at %p\n", (unsigned)code, addr);

    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, "%s at 0x%08X\n",
                ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                (unsigned)ep->ExceptionRecord->ExceptionInformation[1]);
    }

    fprintf(stderr, "EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n",
            g_eax, g_ebx, g_ecx, g_edx);
    fprintf(stderr, "ESI=0x%08X EDI=0x%08X ESP=0x%08X\n",
            g_esi, g_edi, g_esp);
    fprintf(stderr, "g_mem_base=%lld\n", (long long)g_mem_base);
    fprintf(stderr, "Call depth: %u (max %u), calls: %u, icalls: %u\n",
            g_call_depth, g_call_depth_max, g_total_calls, g_total_icalls);

    /* Dump last ICALL targets */
    fprintf(stderr, "\nLast %d ICALL targets:\n", ICALL_TRACE_SIZE);
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        int idx = (g_icall_trace_idx - 1 - i) & (ICALL_TRACE_SIZE - 1);
        if (g_icall_trace[idx]) {
            /* Try to identify the import */
            uint32_t va = g_icall_trace[idx];
            const char* name = "???";
            if (va >= IMPORT_SENTINEL_BASE && va < IMPORT_SENTINEL_BASE + (uint32_t)g_import_count) {
                int imp_idx = (int)(va - IMPORT_SENTINEL_BASE);
                name = g_imports[imp_idx].func_name;
            }
            fprintf(stderr, "  [%2d] 0x%08X (%s)\n", i, va, name);
        }
    }

    /* Dump trace ring */
    fprintf(stderr, "\nLast trace entries:\n");
    int ring_start = (g_trace_ring_idx > 16) ? (int)(g_trace_ring_idx - 16) : 0;
    for (int i = ring_start; i < (int)g_trace_ring_idx && i < ring_start + 16; i++) {
        int idx = i & (TRACE_RING_SIZE - 1);
        if (g_trace_ring[idx][0])
            fprintf(stderr, "  %s", g_trace_ring[idx]);
    }

    fprintf(stderr, "===================================\n");
    fflush(stderr);

    return EXCEPTION_CONTINUE_SEARCH;
}

/*========================================================================
 * Memory Setup
 *========================================================================*/

static int setup_memory(const char* data_file) {
    printf("[*] Setting up memory layout (fixed-base, g_mem_base=0)...\n");

    /* With exe rebased to 0x10000000, we can map at original VAs.
     * g_mem_base = 0 means ADDR(va) = va, so all addresses are real. */
    g_mem_base = 0;

    /* Try to allocate the entire original VA range in one shot:
     * 0x00010000 - 0x00A29000 (covers SEH workaround, stack, and data) */
    void* va_block = VirtualAlloc(
        (void*)0x00010000,
        0x00A29000 - 0x00010000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!va_block) {
        fprintf(stderr, "FATAL: Failed to allocate VA range 0x00010000-0x00A29000 (err %lu)\n",
                GetLastError());
        fprintf(stderr, "    Is the exe rebased to 0x10000000? Check /BASE linker option.\n");
        return 0;
    }
    printf("    VA block:  %p (0x00010000 - 0x00A29000)\n", va_block);

    /* Initialize SEH area — MEM32(0) can't work since VA 0 is null guard.
     * But with g_mem_base=0, MEM32(0) = *(0) which will crash.
     * We'll handle this by catching the access violation in VEH. */
    /* Set 0x00010000 area to 0xFF for SEH chain end */
    memset(va_block, 0xFF, 0x10000);

    /* Stack: 0x00100000 - 0x00200000 (already allocated in block) */
    g_esp = 0x001FFFC0;
    printf("    Stack:     0x00100000 - 0x00200000 (ESP=0x%08X)\n", g_esp);

    /* Data sections are at 0x00603000+ (within our block) */
    printf("    Data:      0x%08X - 0x%08X (%u KB)\n",
           CS_DATA_START, CS_DATA_END, CS_DATA_SIZE / 1024);
    printf("    g_mem_base: %lld (should be 0)\n", (long long)g_mem_base);

    /* Load initialized data from the original binary */
    if (data_file) {
        FILE* f = fopen(data_file, "rb");
        if (!f) {
            fprintf(stderr, "WARNING: Could not open %s\n", data_file);
        } else {
            for (unsigned i = 0; i < NUM_SECTIONS_TO_LOAD; i++) {
                const section_load_t* s = &g_sections_to_load[i];
                fseek(f, s->raw_offset, SEEK_SET);
                size_t n = fread((void*)ADDR(s->va), 1, s->raw_size, f);
                printf("    Loaded VA 0x%08X: %u bytes from offset 0x%X\n",
                       s->va, (unsigned)n, s->raw_offset);
            }
            fclose(f);
        }
    } else {
        fprintf(stderr, "WARNING: No binary file specified — data sections empty\n");
    }

    return 1;
}

static void cleanup_memory(void) {
    /* VirtualAlloc'd regions will be freed when process exits */
}

/*========================================================================
 * Import Bridge Setup
 *
 * Registers all 597 imports with their IAT addresses, DLL names,
 * argument counts, and calling conventions.
 *========================================================================*/

static void setup_imports(void) {
    printf("[*] Setting up import bridges...\n");

    /*
     * Data imports: these IAT slots are read directly (not through ICALL).
     * We write the real data pointer into the IAT slot.
     * Use scratch space at VA 0x00A1E000-0x00A1EFFF for our variables.
     */
    #define SCRATCH_VA 0x00A1E000

    /* _adjust_fdiv: pointer to int (0 = no FDIV bug) */
    MEM32(SCRATCH_VA + 0x00) = 0;
    register_data_import(0x00A202FC, SCRATCH_VA + 0x00);

    /* _iob, _pctype, __mb_cur_max, _HUGE: MSVCRT data exports.
     * These IAT slots are read directly by recompiled code to get pointers
     * to CRT data. The pointers are then passed to native CRT functions,
     * so they must be real addresses (not VAs).
     * We store real addresses directly in the IAT slots. */
    {
        HMODULE hcrt = LoadLibraryA("MSVCRT.dll");
        if (hcrt) {
            void* iob = (void*)GetProcAddress(hcrt, "_iob");
            void* pctype = (void*)GetProcAddress(hcrt, "_pctype");
            void* mbcurmax = (void*)GetProcAddress(hcrt, "__mb_cur_max");
            void* huge = (void*)GetProcAddress(hcrt, "_HUGE");

            if (iob) register_data_import(0x00A201AC, (uint32_t)(uintptr_t)iob);
            if (pctype) register_data_import(0x00A20280, (uint32_t)(uintptr_t)pctype);
            if (mbcurmax) register_data_import(0x00A20288, (uint32_t)(uintptr_t)mbcurmax);
            if (huge) register_data_import(0x00A2035C, (uint32_t)(uintptr_t)huge);

            printf("    _iob=%p _pctype=%p __mb_cur_max=%p _HUGE=%p\n",
                   iob, pctype, mbcurmax, huge);
        }
    }

    /* _adjust_fdiv: pointer to int (0 = no FDIV bug).
     * With g_mem_base=0, VA = real address. Store in our mapped area. */
    MEM32(SCRATCH_VA + 0x00) = 0;
    register_data_import(0x00A202FC, SCRATCH_VA + 0x00);

    /* _acmdln: pointer to char* (command line).
     * Code reads [_acmdln] to get char* then reads the string.
     * Both the pointer and string must be in VA space. */
    {
        uint32_t str_va = SCRATCH_VA + 0x10;
        uint32_t ptr_va = SCRATCH_VA + 0x08;
        const char* cmd = "CRIMSON.EXE";
        memcpy((void*)ADDR(str_va), cmd, strlen(cmd) + 1);
        MEM32(ptr_va) = str_va;
        register_data_import(0x00A2030C, ptr_va);
    }

    /* MSVCP60 data imports */
    /* npos: static const size_t = 0xFFFFFFFF */
    MEM32(SCRATCH_VA + 0x30) = 0xFFFFFFFF;
    register_data_import(0x00A20118, SCRATCH_VA + 0x30);
    /* _C (null char for basic_string) */
    MEM32(SCRATCH_VA + 0x34) = 0;
    register_data_import(0x00A20110, SCRATCH_VA + 0x34);

    #undef SCRATCH_VA

    /*
     * Function imports that need custom bridges (not generic dispatch)
     */
    register_import(0x00A2020C, "MSVCRT.dll", "_purecall", NULL, 0, 0, bridge_purecall);
    register_import(0x00A202E4, "MSVCRT.dll", "__p__commode", NULL, 0, 0, bridge_p_commode);
    register_import(0x00A202F0, "MSVCRT.dll", "__set_app_type", NULL, 0, 0, bridge_set_app_type);
    register_import(0x00A202F4, "MSVCRT.dll", "__p__fmode", NULL, 0, 0, bridge_p_fmode);
    register_import(0x00A202F8, "MSVCRT.dll", "_initterm", NULL, 0, 0, bridge_initterm);
    register_import(0x00A20300, "MSVCRT.dll", "__setusermatherr", NULL, 0, 0, bridge_setusermatherr);
    register_import(0x00A20304, "MSVCRT.dll", "_XcptFilter", NULL, 0, 0, bridge_XcptFilter);
    register_import(0x00A20308, "MSVCRT.dll", "__getmainargs", NULL, 0, 0, bridge_getmainargs);
    register_import(0x00A20310, "MSVCRT.dll", "_except_handler3", NULL, 0, 0, bridge_except_handler3);
    register_import(0x00A20340, "MSVCRT.dll", "__CxxFrameHandler", NULL, 0, 0, bridge_CxxFrameHandler);
    register_import(0x00A202DC, "MSVCRT.dll", "_errno", NULL, 0, 0, bridge_errno);

    /* With g_mem_base=0, malloc/free use real addresses directly.
     * No custom bridges needed — the generic bridge works. */

    /* KERNEL32 functions needing pointer translation */
    register_import(0x00A1FD80, "KeRNeL32.dll", "GetStartupInfoA", NULL, 1, 1, bridge_GetStartupInfoA);
    register_import(0x00A1FD84, "KeRNeL32.dll", "GetModuleHandleA", NULL, 1, 1, bridge_GetModuleHandleA);
    register_import(0x00A1FD18, "KeRNeL32.dll", "GetCommandLineA", NULL, 0, 1, bridge_GetCommandLineA);

    /* All remaining imports — auto-generated from IAT analysis */
#include "imports_gen.inc"

    printf("    Registered %d import bridges\n", g_import_count);
}

/*========================================================================
 * Entry Point
 *========================================================================*/

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)nCmdShow;

    /* Redirect output to file for debugging */
    freopen("crimson_recomp.log", "w", stdout);
    freopen("crimson_recomp.log", "a", stderr);
    setbuf(stdout, NULL);  /* unbuffered for crash debugging */
    setbuf(stderr, NULL);

    printf("Crimson Skies Static Recompilation v0.2\n");
    printf("=======================================\n");
    printf("Binary: CRIMSON.ICD (Zipper Interactive, 2000)\n");
    printf("Engine: GameZ/GOS\n");
    printf("Phase 4: Runtime Bringup\n\n");

    /* Install VEH crash handler first */
    AddVectoredExceptionHandler(1, veh_handler);
    printf("[*] VEH crash handler installed\n");

    /* Determine path to original binary */
    const char* data_file = NULL;
    if (lpCmdLine && lpCmdLine[0]) {
        data_file = lpCmdLine;
    } else {
        /* Try default locations */
        const char* defaults[] = {
            "CRIMSON_decrypted.exe",
            "analysis\\CRIMSON_decrypted.exe",
            "..\\analysis\\CRIMSON_decrypted.exe",
            NULL
        };
        for (int i = 0; defaults[i]; i++) {
            FILE* test = fopen(defaults[i], "rb");
            if (test) {
                fclose(test);
                data_file = defaults[i];
                break;
            }
        }
    }

    if (data_file) {
        printf("[*] Using binary: %s\n", data_file);
    } else {
        fprintf(stderr, "WARNING: No binary file found. Pass path as argument.\n");
        fprintf(stderr, "    Usage: crimson.exe <path-to-CRIMSON_decrypted.exe>\n");
    }

    /* Memory base offset: 0 for fixed-base mapping */
    g_mem_base = 0;

    /* Set up memory layout */
    if (!setup_memory(data_file)) {
        fprintf(stderr, "FATAL: Memory setup failed\n");
        cleanup_memory();
        return 1;
    }

    /* Set up import bridges */
    setup_imports();

    printf("\n[*] Dispatch table: %u recompiled functions\n", recomp_dispatch_count);
    printf("[*] Import bridges: %d registered\n", g_import_count);

    /* Initialize TEB simulation */
    memset(g_fs_seg, 0xFF, sizeof(g_fs_seg));
    g_fs_seg[0] = 0xFFFFFFFF;  /* SEH chain end */
    /* fs:[0x18] = linear address of TEB */
    g_fs_seg[0x18/4] = (uint32_t)(uintptr_t)g_fs_seg;

    /* Call recompiled entry point: CRT startup at 0x005F7056 */
    printf("\n[*] Calling entry point sub_005F7056...\n");
    fflush(stdout);

    /* Set up initial register state matching what the OS loader provides */
    /* hInstance, hPrevInstance, lpCmdLine, nCmdShow on the stack */
    PUSH32(g_esp, (uint32_t)nCmdShow);
    PUSH32(g_esp, (uint32_t)(uintptr_t)lpCmdLine);
    PUSH32(g_esp, 0);  /* hPrevInstance = NULL */
    PUSH32(g_esp, (uint32_t)(uintptr_t)hInstance);
    PUSH32(g_esp, 0xDEAD0000u);  /* fake return address */

    sub_005F7056();

    printf("\n[*] Entry point returned. EAX=0x%08X\n", g_eax);
    printf("[*] Call stats: %u direct, %u indirect, max depth %u\n",
           g_total_calls, g_total_icalls, g_call_depth_max);

    cleanup_memory();
    return (int)g_eax;
}
