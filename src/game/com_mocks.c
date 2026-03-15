/**
 * Crimson Skies Static Recompilation — COM Mock Objects
 *
 * Mock implementations of DirectX COM interfaces:
 *   - IDirectDraw / IDirectDrawSurface (DDraw.dll)
 *   - IDirect3D / IDirect3DDevice (D3D Immediate Mode)
 *   - IDirectInput / IDirectInputDevice (DInput.dll)
 *   - IDirectSound / IDirectSoundBuffer (DSound.dll)
 *   - IDirectPlay (DPlayX.dll)
 *
 * Each mock provides a vtable matching the original COM layout.
 * Methods either forward to a modern backend (D3D11) or return
 * success stubs for features we don't need.
 *
 * Crimson Skies also uses:
 *   - IFC21.dll (Immersion force feedback) — can be fully stubbed
 *   - MFC42.DLL — dynamically linked, can use real DLL or mock
 *   - ROFFILE.dll — ROF archive access, may need reimplementation
 *   - zTiff.dll — TIFF loading, replace with stb_image
 */

#include <windows.h>
#include <stdint.h>

/* COM mock implementations will be built here in Phase 5 */
