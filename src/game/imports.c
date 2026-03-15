/**
 * Crimson Skies Static Recompilation — Import Bridges
 *
 * Maps original IAT entries to Win32/DirectX API implementations.
 * Each bridge translates between the recomp register model and
 * native calling conventions.
 *
 * 461 imports from 19 DLLs to bridge:
 *   KERNEL32 (117), USER32 (94), GDI32 (22), MFC42 (64),
 *   MSVCRT (62), MSVCP60 (10), IFC21 (19), WINMM (14),
 *   AVIFIL32 (9), DDRAW (2), DINPUT (1), DSOUND (1),
 *   DPLAYX (1), zTiff (5), ROFFILE (~8), ole32 (3),
 *   SHELL32 (3), ADVAPI32 (6), comdlg32 (2)
 */

#include <windows.h>
#include <stdint.h>
#include "../recomp/recomp_types.h"

/* Import bridges will be generated/written here as Phase 4-5 progresses */

/* Example bridge pattern (from XWA):
 *
 * void bridge_CreateFileA(void) {
 *     // Args on stack: lpFileName, dwAccess, dwShare, lpSecurity, dwDisp, dwFlags, hTemplate
 *     LPCSTR lpFileName = (LPCSTR)ADDR(STACK32(0));
 *     DWORD dwAccess    = STACK32(4);
 *     DWORD dwShare     = STACK32(8);
 *     // ... etc
 *     HANDLE h = CreateFileA(lpFileName, dwAccess, dwShare, ...);
 *     g_eax = (uint32_t)h;
 *     g_esp += 28; // __stdcall: callee cleans 7 args
 * }
 */
