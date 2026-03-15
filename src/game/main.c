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
double g_st0, g_st1, g_st2, g_st3;
int g_fpu_top;
uint8_t *g_mem_base;

/*========================================================================
 * VEH Crash Handler
 *========================================================================*/

/* Ring buffer for last N dispatch calls (crash diagnostics) */
#define TRACE_SIZE 64
static uint32_t g_trace[TRACE_SIZE];
static int g_trace_idx = 0;

void trace_call(uint32_t addr) {
    g_trace[g_trace_idx++ & (TRACE_SIZE - 1)] = addr;
}

static LONG WINAPI veh_handler(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    PVOID addr = ep->ExceptionRecord->ExceptionAddress;

    fprintf(stderr, "\n=== CRIMSON SKIES RECOMP CRASH ===\n");
    fprintf(stderr, "Exception 0x%08X at %p\n", code, addr);
    fprintf(stderr, "EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n",
            g_eax, g_ebx, g_ecx, g_edx);
    fprintf(stderr, "ESI=0x%08X EDI=0x%08X ESP=0x%08X\n",
            g_esi, g_edi, g_esp);
    fprintf(stderr, "\nLast %d dispatch calls (newest first):\n", TRACE_SIZE);
    for (int i = 0; i < TRACE_SIZE; i++) {
        int idx = (g_trace_idx - 1 - i) & (TRACE_SIZE - 1);
        if (g_trace[idx])
            fprintf(stderr, "  [%2d] 0x%08X\n", i, g_trace[idx]);
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
    /* Install crash handler */
    AddVectoredExceptionHandler(1, veh_handler);

    printf("Crimson Skies Static Recompilation v0.1\n");
    printf("=======================================\n");
    printf("Binary: CRIMSON.ICD (Zipper Interactive, 2000)\n");
    printf("Engine: GameZ/GOS\n");
    printf("PDB:    D:\\zipper\\CrimsonRun\\run\\Crimson.pdb\n\n");

    /* TODO Phase 4: Memory mapping */
    /* TODO Phase 4: Import bridge setup */
    /* TODO Phase 4: CRT initialization */
    /* TODO Phase 4: Jump to recompiled entry point (0x005F7056) */

    printf("Setup complete. Recompiled code not yet wired up.\n");
    return 0;
}
