/**
 * Crimson Skies Static Recompilation — Entry Point
 *
 * Sets up memory mapping, import bridges, VEH crash handler,
 * and launches the recompiled game code.
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "../recomp/recomp_types.h"

/*========================================================================
 * Global Register State
 *========================================================================*/

uint32_t g_eax, g_ecx, g_edx, g_esp;
uint32_t g_ebx, g_esi, g_edi;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
ptrdiff_t g_mem_base;
uint32_t g_fs_seg[256];

/* Dispatch/trace infrastructure */
uint32_t g_icall_trace[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx;
uint32_t g_icall_count;
uint32_t g_call_depth;
uint32_t g_call_depth_max;
uint32_t g_total_calls;
uint32_t g_total_icalls;
int g_heap_check_enabled;
uint32_t g_heap_check_last_ok_call;
uint32_t g_heap_check_last_ok_va;
char g_trace_ring[TRACE_RING_SIZE][TRACE_ENTRY_SIZE];
uint32_t g_trace_ring_idx;

/*========================================================================
 * Dispatch Infrastructure
 *========================================================================*/

recomp_func_t recomp_lookup(uint32_t va) {
    /* Binary search in dispatch table */
    int lo = 0, hi = (int)recomp_dispatch_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint32_t addr = recomp_dispatch_table[mid].address;
        if (addr == va) return recomp_dispatch_table[mid].func;
        if (addr < va) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}

recomp_func_t recomp_lookup_manual(uint32_t va) {
    /* TODO: manual overrides for known functions */
    (void)va;
    return NULL;
}

recomp_func_t recomp_lookup_import(uint32_t va) {
    /* TODO: import bridge lookup */
    (void)va;
    return NULL;
}

int recomp_native_call(uint32_t va) {
    /* TODO: dynamically resolved native functions */
    (void)va;
    return 0;
}

void recomp_register_native(uint32_t addr, const char* name, int nargs) {
    (void)addr; (void)name; (void)nargs;
}

/*========================================================================
 * VEH Crash Handler
 *========================================================================*/

static LONG WINAPI veh_handler(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PVOID addr = ep->ExceptionRecord->ExceptionAddress;

    fprintf(stderr, "\n=== CRIMSON SKIES RECOMP CRASH ===\n");
    fprintf(stderr, "Exception 0x%08X at %p\n", (unsigned)code, addr);
    fprintf(stderr, "EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n",
            g_eax, g_ebx, g_ecx, g_edx);
    fprintf(stderr, "ESI=0x%08X EDI=0x%08X ESP=0x%08X\n",
            g_esi, g_edi, g_esp);
    fprintf(stderr, "Call depth: %u (max %u), calls: %u, icalls: %u\n",
            g_call_depth, g_call_depth_max, g_total_calls, g_total_icalls);
    fprintf(stderr, "\nLast %d ICALL targets:\n", ICALL_TRACE_SIZE);
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        int idx = (g_icall_trace_idx - 1 - i) & (ICALL_TRACE_SIZE - 1);
        if (g_icall_trace[idx])
            fprintf(stderr, "  [%2d] 0x%08X\n", i, g_icall_trace[idx]);
    }
    fprintf(stderr, "===================================\n");
    fflush(stderr);

    return EXCEPTION_CONTINUE_SEARCH;
}

/*========================================================================
 * Entry Point
 *========================================================================*/

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    /* Install crash handler */
    AddVectoredExceptionHandler(1, veh_handler);

    printf("Crimson Skies Static Recompilation v0.1\n");
    printf("=======================================\n");
    printf("Binary: CRIMSON.ICD (Zipper Interactive, 2000)\n");
    printf("Engine: GameZ/GOS\n");
    printf("Functions: %u\n", recomp_dispatch_count);
    printf("\n");

    /* Memory base offset: 0 for fixed-base mapping */
    g_mem_base = 0;

    /* TODO Phase 4: VirtualAlloc data sections at original VAs */
    /* TODO Phase 4: Import bridge setup */
    /* TODO Phase 4: CRT initialization */
    /* TODO Phase 4: Jump to recompiled entry point (0x005F7056) */

    printf("Setup complete. Runtime bringup pending.\n");
    return 0;
}
