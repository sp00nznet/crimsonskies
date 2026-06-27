/*
 * va_holder.dll — VA space reservation DLL for Crimson Skies recompilation.
 *
 * This DLL has image base 0x00010000 and a large BSS section that extends
 * the image to cover VA 0x00011000 through ~0x00A2A000. As a static import
 * of the main EXE, the PE loader maps it BEFORE NLS/locale files and before
 * the process heap grows, preventing those from claiming our target VA ranges.
 *
 * Target VA ranges (all within this DLL's virtual image):
 *   0x00010000 - 0x00020000  SEH guard area (PE header + first section pages)
 *   0x00100000 - 0x00200000  Recompiled game stack
 *   0x00603000 - 0x00A2A000  .rdata/.data/.idata/.rsrc from original binary
 */

#include <windows.h>

/* Large BSS array to extend the image's virtual size.
 * With image base 0x10000 and .text/.rdata taking ~0x2000 of RVA space,
 * .data starts at ~RVA 0x2000 → VA 0x12000. We need to extend to VA 0xA2A000.
 * Required BSS size: 0xA2A000 - 0x12000 = 0xA18000 (~10.3MB).
 * Round up to be safe. */
static char g_va_space[0xA20000];  /* ~10.3MB BSS — not stored on disk */

/* Exported function that touches g_va_space to prevent it from being
 * optimized out. Returns a pointer that the caller can ignore. */
__declspec(dllexport) void* __cdecl va_holder_init(void) {
    return g_va_space;
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
    (void)hDll; (void)dwReason; (void)lpReserved;
    return TRUE;
}
