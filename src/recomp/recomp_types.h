/*
 * Crimson Skies Static Recompilation - Core Type Definitions
 *
 * Global register model, memory access macros, stack operations,
 * condition macros, and indirect call dispatch.
 *
 * All recompiled functions include this header.
 */

#ifndef RECOMP_TYPES_H
#define RECOMP_TYPES_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* ============================================================
 * Global Register Model
 *
 * x86 registers are global variables. ebp is local per-function
 * since most VC6 code uses FPO (Frame Pointer Omission).
 * ============================================================ */

/* Volatile (caller-saved) registers */
extern uint32_t g_eax, g_ecx, g_edx, g_esp;

/* Callee-saved registers (also global for implicit parameter passing) */
extern uint32_t g_ebx, g_esi, g_edi;

/* Segment registers (flat mode Win32 - effectively unused) */
extern uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;

/* Function pointer type for recompiled functions */
typedef void (*recomp_func_t)(void);

/* Dispatch table entry */
typedef struct {
    uint32_t address;
    recomp_func_t func;
} recomp_dispatch_entry_t;

/* Dispatch table (generated) */
extern const recomp_dispatch_entry_t recomp_dispatch_table[];
extern const uint32_t recomp_dispatch_count;

/* ============================================================
 * Register Name Aliases (used in generated code)
 * ============================================================ */

#ifdef RECOMP_GENERATED_CODE
#define eax g_eax
#define ecx g_ecx
#define edx g_edx
#define ebx g_ebx
#define esp g_esp
#define esi g_esi
#define edi g_edi
/* ebp is declared local in each function */
#define _seg_cs g_seg_cs
#define _seg_ds g_seg_ds
#define _seg_es g_seg_es
#define _seg_fs g_seg_fs
#define _seg_gs g_seg_gs
#define _seg_ss g_seg_ss
#endif

/* ============================================================
 * Sub-register Access
 * ============================================================ */

#define LO8(r)       ((uint8_t)((r) & 0xFF))
#define HI8(r)       ((uint8_t)(((r) >> 8) & 0xFF))
#define LO16(r)      ((uint16_t)((r) & 0xFFFF))

#define SET_LO8(r, v)   ((r) = ((r) & 0xFFFFFF00u) | ((uint32_t)(uint8_t)(v)))
#define SET_HI8(r, v)   ((r) = ((r) & 0xFFFF00FFu) | (((uint32_t)(uint8_t)(v)) << 8))
#define SET_LO16(r, v)  ((r) = ((r) & 0xFFFF0000u) | ((uint32_t)(uint16_t)(v)))

/* ============================================================
 * Memory Access
 *
 * The original Crimson Skies binary uses a fixed image base of 0x00400000.
 * We map the original data sections at their original VAs using
 * VirtualAlloc/CreateFileMapping so that address-dependent code
 * works correctly.
 *
 * g_mem_base is the offset from original VA to actual mapped address.
 * For fixed-base mapping, this is 0.
 * ============================================================ */

extern ptrdiff_t g_mem_base;

#define ADDR(va)     ((uintptr_t)(uint32_t)(va) + g_mem_base)

#define MEM8(addr)   (*(volatile uint8_t  *)ADDR(addr))
#define MEM16(addr)  (*(volatile uint16_t *)ADDR(addr))
#define MEM32(addr)  (*(volatile uint32_t *)ADDR(addr))
#define MEM64(addr)  (*(volatile uint64_t *)ADDR(addr))
#define MEMF(addr)   (*(volatile float    *)ADDR(addr))
#define MEMD(addr)   (*(volatile double   *)ADDR(addr))

/* ============================================================
 * FS Segment Access (Thread Environment Block)
 *
 * Win32 uses FS:[0] for the SEH chain head and FS:[0x18] for
 * the linear address of the TEB itself.  We simulate this with
 * a small array so that CRT SEH setup/teardown works correctly.
 * ============================================================ */

extern uint32_t g_fs_seg[256];  /* simulated TEB (1 KB) */

#define FS_ADDR(offset)  ((uintptr_t)g_fs_seg + (uint32_t)(offset))
#define FS_MEM8(offset)  (*(volatile uint8_t  *)FS_ADDR(offset))
#define FS_MEM16(offset) (*(volatile uint16_t *)FS_ADDR(offset))
#define FS_MEM32(offset) (*(volatile uint32_t *)FS_ADDR(offset))
#define FS_MEM64(offset) (*(volatile uint64_t *)FS_ADDR(offset))

/* Set 32-bit values in memory (for rep stosd) */
static inline void MEMSET32(void* dst, uint32_t val, uint32_t count) {
    uint32_t* p = (uint32_t*)dst;
    for (uint32_t i = 0; i < count; i++) p[i] = val;
}

/* ============================================================
 * Stack Operations
 * ============================================================ */

#define PUSH32(sp, val) do { \
    (sp) -= 4; \
    MEM32(sp) = (uint32_t)(val); \
} while(0)

#define POP32_VAL(sp) ({ \
    uint32_t _v = MEM32(sp); \
    (sp) += 4; \
    _v; \
})

/* MSVC doesn't support statement expressions, so use a function */
#ifdef _MSC_VER
static inline uint32_t _pop32(uint32_t* sp) {
    uint32_t v = MEM32(*sp);
    *sp += 4;
    return v;
}
#undef POP32_VAL
#define POP32_VAL(sp) _pop32(&(sp))
#endif

#define PUSHAD() do { \
    uint32_t _tmp_esp = esp; \
    PUSH32(esp, eax); PUSH32(esp, ecx); PUSH32(esp, edx); PUSH32(esp, ebx); \
    PUSH32(esp, _tmp_esp); PUSH32(esp, ebp); PUSH32(esp, esi); PUSH32(esp, edi); \
} while(0)

#define POPAD() do { \
    edi = POP32_VAL(esp); esi = POP32_VAL(esp); ebp = POP32_VAL(esp); \
    esp += 4; /* skip saved ESP */ \
    ebx = POP32_VAL(esp); edx = POP32_VAL(esp); ecx = POP32_VAL(esp); eax = POP32_VAL(esp); \
} while(0)

/* ============================================================
 * Condition Macros
 *
 * Pattern-matched from flag-setter (cmp/test/sub/etc.) to
 * flag-consumer (jcc/setcc/cmovcc).
 * ============================================================ */

/* Compare-based conditions (from cmp a, b) */
#define CMP_EQ(a, b)   ((uint32_t)(a) == (uint32_t)(b))
#define CMP_NE(a, b)   ((uint32_t)(a) != (uint32_t)(b))
#define CMP_B(a, b)    ((uint32_t)(a) < (uint32_t)(b))      /* unsigned < */
#define CMP_BE(a, b)   ((uint32_t)(a) <= (uint32_t)(b))     /* unsigned <= */
#define CMP_A(a, b)    ((uint32_t)(a) > (uint32_t)(b))      /* unsigned > */
#define CMP_AE(a, b)   ((uint32_t)(a) >= (uint32_t)(b))     /* unsigned >= */
#define CMP_L(a, b)    ((int32_t)(a) < (int32_t)(b))        /* signed < */
#define CMP_LE(a, b)   ((int32_t)(a) <= (int32_t)(b))       /* signed <= */
#define CMP_G(a, b)    ((int32_t)(a) > (int32_t)(b))        /* signed > */
#define CMP_GE(a, b)   ((int32_t)(a) >= (int32_t)(b))       /* signed >= */
#define CMP_S(a, b)    ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)  /* sign flag */
#define CMP_NS(a, b)   ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)
#define CMP_O(a, b)    0  /* TODO: overflow detection */
#define CMP_NO(a, b)   1
#define CMP_P(a, b)    0  /* TODO: parity */
#define CMP_NP(a, b)   1

/* Test-based conditions (from test a, b) */
#define TEST_Z(a, b)   (((uint32_t)(a) & (uint32_t)(b)) == 0)
#define TEST_NZ(a, b)  (((uint32_t)(a) & (uint32_t)(b)) != 0)
#define TEST_S(a, b)   ((int32_t)((uint32_t)(a) & (uint32_t)(b)) < 0)
#define TEST_NS(a, b)  ((int32_t)((uint32_t)(a) & (uint32_t)(b)) >= 0)
#define TEST_G(a, b)   ((int32_t)((uint32_t)(a) & (uint32_t)(b)) > 0)     /* test+jg:  positive (>0) */
#define TEST_LE(a, b)  ((int32_t)((uint32_t)(a) & (uint32_t)(b)) <= 0)    /* test+jle: non-positive (<=0) */

/* Bit test (from bt) */
#define BT_CF(base, bit) (((uint32_t)(base) >> ((uint32_t)(bit) & 31)) & 1)

/* ============================================================
 * Bit Manipulation
 * ============================================================ */

#define ROL32(val, n) (((uint32_t)(val) << ((n) & 31)) | ((uint32_t)(val) >> (32 - ((n) & 31))))
#define ROR32(val, n) (((uint32_t)(val) >> ((n) & 31)) | ((uint32_t)(val) << (32 - ((n) & 31))))
#define BSWAP32(val)  ( (((val) & 0xFF) << 24) | (((val) & 0xFF00) << 8) | \
                        (((val) >> 8) & 0xFF00) | (((val) >> 24) & 0xFF) )

/* ============================================================
 * FPU Stack Helpers
 * ============================================================ */

static inline void fp_push_impl(double* st, int* top, double val) {
    /* Shift stack down, push new value */
    for (int i = 7; i > 0; i--) st[i] = st[i-1];
    st[0] = val;
    (*top)++;
}

static inline double fp_pop_impl(double* st, int* top) {
    double val = st[0];
    for (int i = 0; i < 7; i++) st[i] = st[i+1];
    st[7] = 0.0;
    (*top)--;
    return val;
}

#define fp_push(val) fp_push_impl(_st, &_fp_top, (val))
#define fp_pop()     fp_pop_impl(_st, &_fp_top)

/* ============================================================
 * CPUID stub
 * ============================================================ */

static inline void CPUID(uint32_t eax_val, uint32_t ebx_val, uint32_t ecx_val, uint32_t edx_val) {
    /* Return something reasonable for a Pentium III era check */
#ifdef _MSC_VER
    int info[4];
    __cpuid(info, eax_val);
    g_eax = info[0]; g_ebx = info[1]; g_ecx = info[2]; g_edx = info[3];
#else
    (void)eax_val; (void)ebx_val; (void)ecx_val; (void)edx_val;
#endif
}

/* ============================================================
 * Indirect Call Dispatch
 * ============================================================ */

/* ICALL trace ring buffer for crash diagnostics */
#define ICALL_TRACE_SIZE 32
extern uint32_t g_icall_trace[ICALL_TRACE_SIZE];
extern uint32_t g_icall_trace_idx;
extern uint32_t g_icall_count;

/* Call depth tracking */
extern uint32_t g_call_depth;
extern uint32_t g_call_depth_max;

/* Lookup functions */
recomp_func_t recomp_lookup(uint32_t va);          /* binary search in dispatch table */
recomp_func_t recomp_lookup_manual(uint32_t va);    /* manual overrides */
recomp_func_t recomp_lookup_import(uint32_t va);    /* import bridges */
int recomp_native_call(uint32_t va);                /* dynamically resolved native functions */
void recomp_register_native(uint32_t addr, const char* name, int nargs);

/* Total call counter for hang detection */
extern uint32_t g_total_calls;
extern uint32_t g_total_icalls;

/* Heap check after every call (enabled by setting g_heap_check_enabled=1) */
extern int g_heap_check_enabled;
extern uint32_t g_heap_check_last_ok_call;
extern uint32_t g_heap_check_last_ok_va;

/* Trace ring buffer (dumped on hang/exit) */
#define TRACE_RING_SIZE 512
#define TRACE_ENTRY_SIZE 128
extern char g_trace_ring[TRACE_RING_SIZE][TRACE_ENTRY_SIZE];
extern uint32_t g_trace_ring_idx;
#define TRACE_LOG(...) do { \
    snprintf(g_trace_ring[g_trace_ring_idx & (TRACE_RING_SIZE-1)], TRACE_ENTRY_SIZE, __VA_ARGS__); \
    g_trace_ring_idx++; \
} while(0)

/* Direct call to a known recompiled function.
 * Save/restore callee-saved registers (ebx, esi, edi) to enforce the x86
 * calling convention. This masks stack imbalance bugs in recompiled code
 * that would otherwise cause corrupted pop values to propagate. */
#define RECOMP_CALL(func) do { \
    uint32_t _save_ebx = g_ebx, _save_esi = g_esi, _save_edi = g_edi; \
    PUSH32(esp, 0xDEAD0000u); /* dummy return address */ \
    g_call_depth++; \
    g_total_calls++; \
    if (g_call_depth > g_call_depth_max) g_call_depth_max = g_call_depth; \
    TRACE_LOG("[CALL %u d%u] -> %s\n", g_total_calls, g_call_depth, #func); \
    func(); \
    TRACE_LOG("[RET  %u d%u] <- %s\n", g_total_calls, g_call_depth, #func); \
    g_call_depth--; \
    g_ebx = _save_ebx; g_esi = _save_esi; g_edi = _save_edi; \
    if (g_heap_check_enabled && !HeapValidate(GetProcessHeap(), 0, NULL)) { \
        fprintf(stderr, "[HEAP] CORRUPTION after CALL %s (call #%u)\n", #func, g_total_calls); \
        fprintf(stderr, "    Last OK: call #%u va 0x%08X\n", g_heap_check_last_ok_call, g_heap_check_last_ok_va); \
        g_heap_check_enabled = 0; \
    } else if (g_heap_check_enabled) { \
        g_heap_check_last_ok_call = g_total_calls; \
        g_heap_check_last_ok_va = 0; \
    } \
} while(0)

/* Indirect call through dispatch.
 * Same callee-saved register protection as RECOMP_CALL. */
#define RECOMP_ICALL(target_va) do { \
    uint32_t _va = (uint32_t)(target_va); \
    uint32_t _save_ebx = g_ebx, _save_esi = g_esi, _save_edi = g_edi; \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    g_total_icalls++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (_fn) { \
        PUSH32(esp, 0xDEAD0000u); \
        g_call_depth++; \
        if (g_call_depth > g_call_depth_max) g_call_depth_max = g_call_depth; \
        TRACE_LOG("[ICALL %u d%u] -> 0x%08X\n", g_total_icalls, g_call_depth, _va); \
        _fn(); \
        TRACE_LOG("[IRET  %u d%u] <- 0x%08X\n", g_total_icalls, g_call_depth, _va); \
        g_call_depth--; \
        g_ebx = _save_ebx; g_esi = _save_esi; g_edi = _save_edi; \
        if (g_heap_check_enabled && !HeapValidate(GetProcessHeap(), 0, NULL)) { \
            fprintf(stderr, "[HEAP] CORRUPTION after ICALL 0x%08X in %s (icall #%u, call #%u)\n", _va, __func__, g_total_icalls, g_total_calls); \
            fprintf(stderr, "    Last OK: call #%u va 0x%08X\n", g_heap_check_last_ok_call, g_heap_check_last_ok_va); \
            g_heap_check_enabled = 0; \
        } else if (g_heap_check_enabled) { \
            g_heap_check_last_ok_call = g_total_calls; \
            g_heap_check_last_ok_va = _va; \
        } \
    } else { \
        PUSH32(esp, 0xDEAD0000u); \
        TRACE_LOG("[ICALL %u d%u] -> native 0x%08X\n", g_total_icalls, g_call_depth, _va); \
        if (!recomp_native_call(_va)) { \
            esp += 4; /* undo push */ \
            TRACE_LOG("ICALL: unresolved VA 0x%08X\n", _va); \
            fprintf(stderr, "!!! UNRESOLVED ICALL: VA 0x%08X (call #%u, icall #%u) in %s\n", _va, g_total_calls, g_total_icalls, __func__); \
            eax = 0; \
        } \
        g_ebx = _save_ebx; g_esi = _save_esi; g_edi = _save_edi; \
    } \
} while(0)

/* Indirect tail call (jmp through dispatch) */
#define RECOMP_ITAIL(target_va) do { \
    uint32_t _va = (uint32_t)(target_va); \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    g_total_icalls++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (_fn) { \
        g_call_depth++; \
        if (g_call_depth > g_call_depth_max) g_call_depth_max = g_call_depth; \
        TRACE_LOG("[ITAIL %u d%u] -> 0x%08X\n", g_total_icalls, g_call_depth, _va); \
        _fn(); \
        g_call_depth--; \
    } else if (!recomp_native_call(_va)) { \
        TRACE_LOG("ITAIL: unresolved VA 0x%08X\n", _va); \
        fprintf(stderr, "!!! UNRESOLVED ITAIL: VA 0x%08X (call #%u, icall #%u) in %s\n", _va, g_total_calls, g_total_icalls, __func__); \
        fprintf(stderr, "    Last 16 ICALL/ITAIL targets:\n"); \
        for (int _i = 16; _i > 0; _i--) { \
            uint32_t _idx = (g_icall_trace_idx - _i) & (ICALL_TRACE_SIZE-1); \
            fprintf(stderr, "      [-%d] 0x%08X\n", _i, g_icall_trace[_idx]); \
        } \
        fprintf(stderr, "    g_esp=0x%08X\n", g_esp); \
    } \
} while(0)

/* Stub macro for unimplemented imports */
#define STUB(name) do { \
    static int _warned = 0; \
    if (!_warned) { fprintf(stderr, "STUB: %s called\n", name); _warned = 1; } \
} while(0)

/* Heap validation helper */
#ifdef _WIN32
#ifndef _WINDOWS_  /* avoid redecl if windows.h already included */
__declspec(dllimport) void* __stdcall GetProcessHeap(void);
__declspec(dllimport) int   __stdcall HeapValidate(void*, unsigned long, const void*);
#endif
static inline void recomp_heap_check(const char* where) {
    if (!HeapValidate(GetProcessHeap(), 0, NULL))
        fprintf(stderr, "[HEAP] CORRUPTION detected at %s\n", where);
}
#else
static inline void recomp_heap_check(const char* where) { (void)where; }
#endif

#endif /* RECOMP_TYPES_H */
