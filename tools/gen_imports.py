#!/usr/bin/env python3
"""Generate import bridge registration code from IAT JSON data."""
import json
import sys

with open('analysis/iat_imports.json') as f:
    iat = json.load(f)

# Known calling conventions and arg counts
# (nargs, is_stdcall)  stdcall=1, cdecl=0
known = {
    # KERNEL32.dll (all stdcall)
    'lstrcmpA': (2, 1), 'lstrcatA': (2, 1), 'lstrcpyA': (2, 1), 'lstrlenA': (1, 1),
    'IsDBCSLeadByte': (1, 1), 'lstrcpynA': (3, 1), 'lstrcmpiA': (2, 1),
    'GetTimeFormatA': (6, 1), 'GetDateFormatA': (6, 1),
    'FileTimeToSystemTime': (2, 1), 'CompareFileTime': (2, 1),
    'LocalFree': (1, 1), 'FormatMessageA': (7, 1),
    'SetLastError': (1, 1), 'DeleteFileA': (1, 1),
    'CloseHandle': (1, 1), 'GetLastError': (0, 1),
    'CreateFileA': (7, 1), 'SetFileAttributesA': (2, 1),
    'WriteFile': (5, 1), 'CreateDirectoryA': (2, 1),
    'GetTempPathA': (2, 1), 'RemoveDirectoryA': (1, 1),
    'GetStringTypeExA': (5, 1), 'IsBadStringPtrA': (2, 1),
    'GetFileAttributesA': (1, 1), 'GetLocaleInfoA': (4, 1),
    'GetProcAddress': (2, 1), 'MoveFileA': (2, 1),
    'FreeLibrary': (1, 1), 'GetPrivateProfileStringA': (6, 1),
    'LoadLibraryA': (1, 1), 'FindNextFileA': (2, 1),
    'FindFirstFileA': (2, 1), 'FindClose': (1, 1),
    'GetFullPathNameA': (4, 1), 'WaitForSingleObject': (2, 1),
    'GetShortPathNameA': (3, 1), 'ExitProcess': (1, 1),
    'GetCommandLineA': (0, 1), 'Sleep': (1, 1),
    'ReleaseMutex': (1, 1), 'GetUserDefaultLangID': (0, 1),
    'CreateMutexA': (3, 1), 'GetFileSize': (2, 1),
    'OutputDebugStringA': (1, 1), 'ReadFile': (5, 1),
    'GetFileTime': (4, 1), 'GetTickCount': (0, 1),
    'SetFilePointer': (4, 1), 'GetLogicalDriveStringsA': (2, 1),
    'MultiByteToWideChar': (6, 1), 'GetDriveTypeA': (1, 1),
    'SetThreadPriority': (2, 1), 'CreateThread': (6, 1),
    'ResumeThread': (1, 1), 'GetProcessAffinityMask': (3, 1),
    'GetCurrentProcess': (0, 1), 'GlobalMemoryStatus': (1, 1),
    'QueryPerformanceCounter': (1, 1), 'QueryPerformanceFrequency': (1, 1),
    'GetThreadPriority': (1, 1), 'GetCurrentThread': (0, 1),
    'GetCPInfo': (2, 1), 'LocalAlloc': (2, 1),
    'GetStartupInfoA': (1, 1), 'GetModuleHandleA': (1, 1),
    'EnterCriticalSection': (1, 1), 'LeaveCriticalSection': (1, 1),
    'DeleteCriticalSection': (1, 1), 'InitializeCriticalSection': (1, 1),
    'GetACP': (0, 1), 'CompareStringA': (6, 1),
    'GetVersionExA': (1, 1), 'WideCharToMultiByte': (8, 1),
    'GetCurrentThreadId': (0, 1), 'GetCurrentProcessId': (0, 1),
    'TlsAlloc': (0, 1), 'TlsFree': (1, 1), 'TlsGetValue': (1, 1), 'TlsSetValue': (2, 1),
    'GetSystemTime': (1, 1), 'GetLocalTime': (1, 1), 'GetSystemInfo': (1, 1),
    'VirtualAlloc': (4, 1), 'VirtualFree': (3, 1), 'VirtualProtect': (4, 1),
    'VirtualQuery': (3, 1), 'HeapCreate': (3, 1), 'HeapDestroy': (1, 1),
    'HeapAlloc': (3, 1), 'HeapReAlloc': (4, 1), 'HeapFree': (3, 1),
    'HeapSize': (3, 1), 'GetProcessHeap': (0, 1),
    'GlobalAlloc': (2, 1), 'GlobalFree': (1, 1), 'GlobalLock': (1, 1), 'GlobalUnlock': (1, 1),
    'SetFilePointer': (4, 1), 'GetModuleFileNameA': (3, 1),
    'CopyFileA': (3, 1), 'GetPrivateProfileIntA': (4, 1),
    'WritePrivateProfileStringA': (4, 1), 'ExitThread': (1, 1),
    'SetCurrentDirectoryA': (1, 1), 'GetCurrentDirectoryA': (2, 1),
    'SetEndOfFile': (1, 1), 'FlushFileBuffers': (1, 1),
    'GetSystemDirectoryA': (2, 1), 'GetWindowsDirectoryA': (2, 1),
    'GetTempFileNameA': (4, 1), 'LockFile': (5, 1), 'UnlockFile': (5, 1),
    'CreateEventA': (4, 1), 'SetEvent': (1, 1), 'ResetEvent': (1, 1),
    'HeapValidate': (3, 1), 'GetComputerNameA': (2, 1),
    'InterlockedIncrement': (1, 1), 'InterlockedDecrement': (1, 1),
    'InterlockedExchange': (2, 1),
    # USER32.dll (all stdcall)
    'RegisterWindowMessageA': (1, 1), 'LoadBitmapA': (2, 1),
    'MsgWaitForMultipleObjects': (5, 1), 'SetRect': (5, 1),
    'IsCharAlphaNumericA': (1, 1), 'PostQuitMessage': (1, 1),
    'AdjustWindowRectEx': (4, 1), 'GetMenu': (1, 1),
    'SystemParametersInfoA': (4, 1), 'GetWindowRect': (2, 1),
    'ShowWindow': (2, 1), 'OpenIcon': (1, 1),
    'EqualRect': (2, 1), 'SetWindowPos': (7, 1),
    'ReleaseDC': (2, 1), 'DrawTextExA': (6, 1),
    'IntersectRect': (3, 1), 'PeekMessageA': (5, 1),
    'GetKeyboardType': (1, 1), 'ClientToScreen': (2, 1),
    'GetKeyNameTextA': (3, 1), 'GetKeyboardState': (1, 1),
    'MapVirtualKeyA': (2, 1), 'ToAscii': (5, 1),
    'MessageBeep': (1, 1), 'MessageBoxExA': (5, 1),
    'UnregisterClassA': (2, 1), 'GetLastActivePopup': (1, 1),
    'IsIconic': (1, 1), 'CharNextA': (1, 1),
    'GetClientRect': (2, 1), 'GetDC': (1, 1),
    'TranslateMessage': (1, 1), 'OffsetRect': (3, 1),
    'GetKeyboardLayout': (1, 1), 'DispatchMessageA': (1, 1),
    'SetFocus': (1, 1), 'CharPrevA': (2, 1),
    'SetCursorPos': (2, 1), 'GetSystemMetrics': (1, 1),
    'LoadMenuA': (2, 1), 'SetWindowLongA': (3, 1),
    'PostMessageA': (4, 1), 'FindWindowA': (2, 1),
    'SetForegroundWindow': (1, 1), 'DefWindowProcA': (4, 1),
    'LoadIconA': (2, 1), 'LoadCursorA': (2, 1),
    'UpdateWindow': (1, 1), 'ClipCursor': (1, 1),
    'ShowCursor': (1, 1), 'RemoveMenu': (3, 1),
    'GetWindowLongA': (2, 1), 'GetParent': (1, 1),
    'MessageBoxA': (4, 1), 'LoadStringA': (4, 1),
    'CheckMenuItem': (3, 1), 'InvalidateRect': (3, 1),
    'SetMenu': (2, 1), 'SendMessageA': (4, 1),
    'GetKeyState': (1, 1), 'EnableWindow': (2, 1),
    'RegisterClassA': (1, 1), 'CreateWindowExA': (12, 1),
    'DestroyWindow': (1, 1), 'GetMessageA': (4, 1),
    'SetWindowTextA': (2, 1), 'GetWindowTextA': (3, 1),
    'AdjustWindowRect': (3, 1), 'SetCapture': (1, 1),
    'ReleaseCapture': (0, 1), 'GetDlgItem': (2, 1),
    'SetDlgItemTextA': (3, 1), 'CheckDlgButton': (3, 1),
    'IsDlgButtonChecked': (2, 1), 'EndDialog': (2, 1),
    'DialogBoxParamA': (5, 1), 'GetForegroundWindow': (0, 1),
    'GetFocus': (0, 1), 'SetTimer': (4, 1), 'KillTimer': (2, 1),
    'GetDesktopWindow': (0, 1), 'GetAsyncKeyState': (1, 1),
    'IsWindow': (1, 1), 'GetCursorPos': (1, 1),
    'ScreenToClient': (2, 1), 'CallWindowProcA': (5, 1),
    # GDI32.dll (all stdcall)
    'SetBkColor': (2, 1), 'SetBkMode': (2, 1), 'CreateFontA': (14, 1),
    'SetTextColor': (2, 1), 'GetTextMetricsA': (2, 1),
    'SaveDC': (1, 1), 'GetStockObject': (1, 1), 'RestoreDC': (2, 1),
    'BitBlt': (9, 1), 'SetStretchBltMode': (2, 1), 'StretchBlt': (11, 1),
    'CreateCompatibleDC': (1, 1), 'CreateDIBSection': (6, 1),
    'SelectObject': (2, 1), 'GetDeviceCaps': (2, 1),
    'GetSystemPaletteEntries': (4, 1), 'GetObjectA': (3, 1),
    'PatBlt': (6, 1), 'DeleteObject': (1, 1),
    'CreateFontIndirectA': (1, 1), 'DeleteDC': (1, 1),
    'GetTextExtentPoint32A': (4, 1),
    # ADVAPI32.dll
    'RegQueryValueExA': (6, 1), 'RegOpenKeyExA': (5, 1),
    'RegCloseKey': (1, 1), 'RegSetValueExA': (6, 1),
    'RegCreateKeyExA': (9, 1), 'RegDeleteKeyA': (2, 1),
    'RegDeleteValueA': (2, 1),
    # WINMM.dll
    'mixerGetLineInfoA': (3, 1), 'mixerOpen': (5, 1),
    'mciGetErrorStringA': (3, 1), 'mixerGetLineControlsA': (3, 1),
    'mixerClose': (1, 1), 'auxSetVolume': (2, 1),
    'auxGetVolume': (2, 1), 'mciSendCommandA': (4, 1),
    'auxGetNumDevs': (0, 1), 'auxGetDevCapsA': (3, 1),
    'mixerSetControlDetails': (3, 1), 'mixerGetControlDetailsA': (3, 1),
    'mixerGetNumDevs': (0, 1), 'timeGetTime': (0, 1),
    # ole32.dll
    'CoInitialize': (1, 1), 'CoCreateInstance': (5, 1), 'CoUninitialize': (0, 1),
    # SHELL32.dll
    'SHGetPathFromIDListA': (2, 1), 'ShellExecuteA': (6, 1),
    'SHGetSpecialFolderLocation': (3, 1),
    # comdlg32.dll
    'GetSaveFileNameA': (1, 1), 'GetOpenFileNameA': (1, 1),
    # IMM32.dll
    'ImmGetVirtualKey': (1, 1),
    # DDRAW.dll
    'DirectDrawCreate': (3, 1), 'DirectDrawEnumerateA': (2, 1),
    # DINPUT.dll
    'DirectInputCreateA': (4, 1),
    # AVIFIL32.dll
    'AVIFileInit': (0, 1), 'AVIStreamFindSample': (3, 1),
    'AVIFileExit': (0, 1), 'AVIStreamRead': (7, 1),
    'AVIStreamOpenFromFileA': (6, 1), 'AVIStreamReadFormat': (4, 1),
    'AVIStreamLength': (1, 1), 'AVIStreamRelease': (1, 1),
    'AVIStreamInfoA': (3, 1),
    # MSACM32.dll
    'acmStreamPrepareHeader': (3, 1), 'acmStreamOpen': (8, 1),
    'acmStreamUnprepareHeader': (3, 1), 'acmStreamClose': (2, 1),
    'acmStreamSize': (4, 1), 'acmMetrics': (3, 1),
    'acmStreamConvert': (3, 1), 'acmFormatSuggest': (5, 1),
    # MSVFW32.dll
    'ICDecompress': (8, 1), 'ICLocate': (5, 1),
    'ICClose': (1, 1), 'ICSendMessage': (4, 1),
    # MSVCRT.dll (cdecl)
    '_fullpath': (3, 0), '_chmod': (2, 0), 'rename': (2, 0),
    'strstr': (2, 0), 'fflush': (1, 0), '_CIasin': (0, 0),
    '_beginthreadex': (6, 0), 'isupper': (1, 0), 'isspace': (1, 0),
    'strtok': (2, 0), 'time': (1, 0), 'calloc': (2, 0),
    '_stat': (2, 0), 'atof': (1, 0), 'memmove': (3, 0),
    'toupper': (1, 0), 'strrchr': (2, 0), 'tolower': (1, 0),
    'fprintf': (3, 0), '_access': (2, 0), 'srand': (1, 0),
    'floor': (2, 0), '_rmtmp': (0, 0), '_vsnprintf': (4, 0),
    'wctomb': (2, 0), '_isnan': (2, 0), '_CIfmod': (0, 0),
    '_splitpath': (5, 0), 'fread': (4, 0), 'exit': (1, 0),
    'malloc': (1, 0), 'free': (1, 0), 'strncpy': (3, 0),
    'sprintf': (3, 0), '_stricmp': (2, 0), '_strdup': (1, 0),
    'fopen': (2, 0), 'fgets': (3, 0), 'vsprintf': (3, 0),
    '_exit': (1, 0), 'isleadbyte': (1, 0), '_mbscpy': (2, 0),
    '_mbstrlen': (1, 0), 'setlocale': (2, 0), 'isprint': (1, 0),
    '_controlfp': (2, 0), 'fclose': (1, 0), 'atoi': (1, 0),
    'sscanf': (3, 0), '_itoa': (3, 0), '_strnicmp': (3, 0),
    'strchr': (2, 0), 'isdigit': (1, 0), 'atol': (1, 0),
    'ceil': (2, 0), 'fseek': (3, 0), 'ftell': (1, 0),
    'rewind': (1, 0), 'fscanf': (3, 0), 'strncat': (3, 0),
    '_copysign': (4, 0), '_isctype': (2, 0),
    '_snprintf': (4, 0), 'strtod': (2, 0), 'strtol': (3, 0),
    'ctime': (1, 0), 'freopen': (3, 0),
    '_findclose': (1, 0), '_findnext': (2, 0), '_findfirst': (2, 0),
    'fgetc': (1, 0), 'strpbrk': (2, 0), 'iswspace': (1, 0),
    'difftime': (2, 0), 'strlen': (1, 0), 'strcmp': (2, 0),
    'memcpy': (3, 0), 'memset': (3, 0), 'abs': (1, 0),
    'tmpfile': (0, 0), '_mkdir': (1, 0), 'fwrite': (4, 0),
    '__RTtypeid': (1, 0), '_ftol': (0, 0), 'qsort': (4, 0),
    '??1type_info@@UAE@XZ': (1, 0), '?terminate@@YAXXZ': (0, 0),
    'abort': (0, 0), '_onexit': (1, 0), '__dllonexit': (3, 0),
    '_mbsinc': (1, 0), '_mbsninc': (2, 0), '_mbsnextc': (1, 0),
    '??8type_info@@QBEHABV0@@Z': (2, 0), 'realloc': (2, 0),
    '__RTDynamicCast': (5, 0), 'printf': (2, 0), 'strncmp': (3, 0),
    '_CIacos': (0, 0), 'rand': (0, 0), 'remove': (1, 0),
    '_CIpow': (0, 0), '_strcmpi': (2, 0), '_strupr': (1, 0),
    '_strlwr': (1, 0), '_swab': (3, 0), '_setmbcp': (1, 0),
}

# Imports that need custom bridge functions (defined in main.c)
specials = {
    '_except_handler3', '__CxxFrameHandler', '_purecall',
    '__set_app_type', '__p__fmode', '__p__commode', '_adjust_fdiv',
    '_initterm', '__getmainargs', '__setusermatherr', '_XcptFilter',
    '_acmdln', '_iob', '_pctype', '__mb_cur_max', '_HUGE', '_errno',
}

# DLLs known to default to stdcall
stdcall_dlls = {
    'KeRNeL32.dll', 'USER32.dll', 'GDI32.dll', 'ADVAPI32.dll',
    'WINMM.dll', 'ole32.dll', 'SHELL32.dll', 'comdlg32.dll',
    'IMM32.dll', 'DDRAW.dll', 'DINPUT.dll', 'DSOUND.dll',
    'DPLAYX.dll', 'AVIFIL32.dll', 'MSACM32.dll', 'MSVFW32.dll',
    'MFC42.DLL', 'IFC21.dll', 'zTiff.dll',
}

lines = []
for dll, funcs in sorted(iat.items()):
    lines.append(f'    /* === {dll} ({len(funcs)} imports) === */')
    for func in funcs:
        va = func['iat_va']
        name = func['name']

        if name in specials:
            lines.append(f'    /* 0x{va:08X} {name} -- custom bridge (registered separately) */')
            continue

        if name.startswith('ordinal_'):
            ordinal = int(name.split('_')[1])
            if dll == 'MFC42.DLL':
                # MFC42 exports are a mix of stdcall and thiscall.
                # Use stdcall with 4 default args — callee-cleans is the same.
                # For thiscall methods, ECX needs to be correct; we handle
                # that by leaving g_ecx as the recomp code set it.
                lines.append(f'    register_import_ordinal(0x{va:08X}, "{dll}", {ordinal}, 4, 1);')
            else:
                lines.append(f'    register_import_ordinal(0x{va:08X}, "{dll}", {ordinal}, 0, 1);')
        elif name in known:
            nargs, is_stdcall = known[name]
            lines.append(f'    register_import_auto(0x{va:08X}, "{dll}", "{name}", {nargs}, {is_stdcall});')
        else:
            if dll in ('MFC42.DLL', 'MSVCP60.dll', 'IFC21.dll'):
                # C++ DLLs use __thiscall for most methods
                lines.append(f'    register_import_auto(0x{va:08X}, "{dll}", "{name}", 2, 2); /* thiscall, TODO: nargs */')
            else:
                is_stdcall = 1 if dll in stdcall_dlls else 0
                lines.append(f'    register_import_auto(0x{va:08X}, "{dll}", "{name}", 0, {is_stdcall}); /* TODO: nargs */')

output = '\n'.join(lines)
with open('src/game/imports_gen.inc', 'w') as f:
    f.write(output)

print(f"Generated {len(lines)} lines for {sum(len(v) for v in iat.values())} imports")
print(f"Known arg counts: {sum(1 for dll, funcs in iat.items() for func in funcs if func['name'] in known)}")
print(f"Custom bridges: {sum(1 for dll, funcs in iat.items() for func in funcs if func['name'] in specials)}")
print(f"Unknown/stub: {sum(1 for dll, funcs in iat.items() for func in funcs if func['name'] not in known and func['name'] not in specials and not func['name'].startswith('ordinal_'))}")
print(f"Ordinals: {sum(1 for dll, funcs in iat.items() for func in funcs if func['name'].startswith('ordinal_'))}")
