    /* === ADVAPI32.dll (6 imports) === */
    register_import_auto(0x00A1FB60, "ADVAPI32.dll", "RegQueryValueExA", 6, 1);
    register_import_auto(0x00A1FB64, "ADVAPI32.dll", "RegOpenKeyExA", 5, 1);
    register_import_auto(0x00A1FB68, "ADVAPI32.dll", "RegCloseKey", 1, 1);
    register_import_auto(0x00A1FB6C, "ADVAPI32.dll", "RegSetValueExA", 6, 1);
    register_import_auto(0x00A1FB70, "ADVAPI32.dll", "RegCreateKeyExA", 9, 1);
    register_import_auto(0x00A1FB74, "ADVAPI32.dll", "RegDeleteKeyA", 2, 1);
    /* === AVIFIL32.dll (9 imports) === */
    register_import_auto(0x00A1FB7C, "AVIFIL32.dll", "AVIFileInit", 0, 1);
    register_import_auto(0x00A1FB80, "AVIFIL32.dll", "AVIStreamFindSample", 3, 1);
    register_import_auto(0x00A1FB84, "AVIFIL32.dll", "AVIFileExit", 0, 1);
    register_import_auto(0x00A1FB88, "AVIFIL32.dll", "AVIStreamRead", 7, 1);
    register_import_auto(0x00A1FB8C, "AVIFIL32.dll", "AVIStreamOpenFromFileA", 6, 1);
    register_import_auto(0x00A1FB90, "AVIFIL32.dll", "AVIStreamReadFormat", 4, 1);
    register_import_auto(0x00A1FB94, "AVIFIL32.dll", "AVIStreamLength", 1, 1);
    register_import_auto(0x00A1FB98, "AVIFIL32.dll", "AVIStreamRelease", 1, 1);
    register_import_auto(0x00A1FB9C, "AVIFIL32.dll", "AVIStreamInfoA", 3, 1);
    /* === DDRAW.dll (2 imports) === */
    register_import_auto(0x00A1FBA4, "DDRAW.dll", "DirectDrawCreate", 3, 1);
    register_import_auto(0x00A1FBA8, "DDRAW.dll", "DirectDrawEnumerateA", 2, 1);
    /* === DINPUT.dll (1 imports) === */
    register_import_auto(0x00A1FBB0, "DINPUT.dll", "DirectInputCreateA", 4, 1);
    /* === DPLAYX.dll (1 imports) === */
    register_import_ordinal(0x00A1FBB8, "DPLAYX.dll", 4, 0, 1);
    /* === DSOUND.dll (1 imports) === */
    register_import_ordinal(0x00A1FBC0, "DSOUND.dll", 1, 0, 1);
    /* === GDI32.dll (22 imports) === */
    register_import_auto(0x00A1FBC8, "GDI32.dll", "SetBkColor", 2, 1);
    register_import_auto(0x00A1FBCC, "GDI32.dll", "SetBkMode", 2, 1);
    register_import_auto(0x00A1FBD0, "GDI32.dll", "CreateFontA", 14, 1);
    register_import_auto(0x00A1FBD4, "GDI32.dll", "SetTextColor", 2, 1);
    register_import_auto(0x00A1FBD8, "GDI32.dll", "GetTextMetricsA", 2, 1);
    register_import_auto(0x00A1FBDC, "GDI32.dll", "SaveDC", 1, 1);
    register_import_auto(0x00A1FBE0, "GDI32.dll", "GetStockObject", 1, 1);
    register_import_auto(0x00A1FBE4, "GDI32.dll", "RestoreDC", 2, 1);
    register_import_auto(0x00A1FBE8, "GDI32.dll", "BitBlt", 9, 1);
    register_import_auto(0x00A1FBEC, "GDI32.dll", "SetStretchBltMode", 2, 1);
    register_import_auto(0x00A1FBF0, "GDI32.dll", "StretchBlt", 11, 1);
    register_import_auto(0x00A1FBF4, "GDI32.dll", "CreateCompatibleDC", 1, 1);
    register_import_auto(0x00A1FBF8, "GDI32.dll", "CreateDIBSection", 6, 1);
    register_import_auto(0x00A1FBFC, "GDI32.dll", "SelectObject", 2, 1);
    register_import_auto(0x00A1FC00, "GDI32.dll", "GetDeviceCaps", 2, 1);
    register_import_auto(0x00A1FC04, "GDI32.dll", "GetSystemPaletteEntries", 4, 1);
    register_import_auto(0x00A1FC08, "GDI32.dll", "GetObjectA", 3, 1);
    register_import_auto(0x00A1FC0C, "GDI32.dll", "PatBlt", 6, 1);
    register_import_auto(0x00A1FC10, "GDI32.dll", "DeleteObject", 1, 1);
    register_import_auto(0x00A1FC14, "GDI32.dll", "CreateFontIndirectA", 1, 1);
    register_import_auto(0x00A1FC18, "GDI32.dll", "DeleteDC", 1, 1);
    register_import_auto(0x00A1FC1C, "GDI32.dll", "GetTextExtentPoint32A", 4, 1);
    /* === IFC21.dll (19 imports) === */
    register_import_auto(0x00A1FC24, "IFC21.dll", "??0CImmProject@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC28, "IFC21.dll", "?GetContainedEffect@CImmCompoundEffect@@QAEPAVCImmEffect@@J@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC2C, "IFC21.dll", "??0CImmDXDevice@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC30, "IFC21.dll", "?SwitchToAbsoluteMode@CImmDevice@@UAEHH@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC34, "IFC21.dll", "?Start@CImmCompoundEffect@@QAEHKK@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC38, "IFC21.dll", "?ChangeBaseParams@CImmEffect@@QAEHJJKPAUFEELIT_ENVELOPE@@KKKKK@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC3C, "IFC21.dll", "?ChangeBaseParamsPolar@CImmEffect@@QAEHJKPAUFEELIT_ENVELOPE@@KKKKK@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC40, "IFC21.dll", "?Stop@CImmCompoundEffect@@QAEHXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC44, "IFC21.dll", "?Close@CImmProject@@QAEXXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC48, "IFC21.dll", "??1CImmDXDevice@@UAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC4C, "IFC21.dll", "??1CImmProject@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC50, "IFC21.dll", "?GetAPI@CImmDXDevice@@UAEPAUIFeelit@@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC54, "IFC21.dll", "?Initialize@CImmDXDevice@@QAEHPAX0PAUIDirectInputA@@PAUIDirectInputDevice2A@@@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC58, "IFC21.dll", "?OpenFile@CImmProject@@QAEHPBDPAVCImmDevice@@@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC5C, "IFC21.dll", "?CreateEffect@CImmProject@@QAEPAVCImmCompoundEffect@@PBDPAVCImmDevice@@K@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC60, "IFC21.dll", "?prepare_device@CImmDevice@@MAEHXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC64, "IFC21.dll", "?GetDevice@CImmDXDevice@@UAEPAUIFeelitDevice@@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC68, "IFC21.dll", "?ChangeScreenResolution@CImmDevice@@UAEHHKK@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A1FC6C, "IFC21.dll", "?reset@CImmDXDevice@@MAEXXZ", 2, 2); /* thiscall, TODO: nargs */
    /* === IMM32.dll (1 imports) === */
    register_import_auto(0x00A1FC74, "IMM32.dll", "ImmGetVirtualKey", 1, 1);
    /* === KeRNeL32.dll (74 imports) === */
    register_import_auto(0x00A1FC7C, "KeRNeL32.dll", "lstrcmpA", 2, 1);
    register_import_auto(0x00A1FC80, "KeRNeL32.dll", "lstrcatA", 2, 1);
    register_import_auto(0x00A1FC84, "KeRNeL32.dll", "lstrcpyA", 2, 1);
    register_import_auto(0x00A1FC88, "KeRNeL32.dll", "lstrlenA", 1, 1);
    register_import_auto(0x00A1FC8C, "KeRNeL32.dll", "IsDBCSLeadByte", 1, 1);
    register_import_auto(0x00A1FC90, "KeRNeL32.dll", "lstrcpynA", 3, 1);
    register_import_auto(0x00A1FC94, "KeRNeL32.dll", "lstrcmpiA", 2, 1);
    register_import_auto(0x00A1FC98, "KeRNeL32.dll", "GetTimeFormatA", 6, 1);
    register_import_auto(0x00A1FC9C, "KeRNeL32.dll", "GetDateFormatA", 6, 1);
    register_import_auto(0x00A1FCA0, "KeRNeL32.dll", "FileTimeToSystemTime", 2, 1);
    register_import_auto(0x00A1FCA4, "KeRNeL32.dll", "CompareFileTime", 2, 1);
    register_import_auto(0x00A1FCA8, "KeRNeL32.dll", "LocalFree", 1, 1);
    register_import_auto(0x00A1FCAC, "KeRNeL32.dll", "FormatMessageA", 7, 1);
    register_import_auto(0x00A1FCB0, "KeRNeL32.dll", "SetLastError", 1, 1);
    register_import_auto(0x00A1FCB4, "KeRNeL32.dll", "DeleteFileA", 1, 1);
    register_import_auto(0x00A1FCB8, "KeRNeL32.dll", "CloseHandle", 1, 1);
    register_import_auto(0x00A1FCBC, "KeRNeL32.dll", "GetLastError", 0, 1);
    register_import_auto(0x00A1FCC0, "KeRNeL32.dll", "CreateFileA", 7, 1);
    register_import_auto(0x00A1FCC4, "KeRNeL32.dll", "SetFileAttributesA", 2, 1);
    register_import_auto(0x00A1FCC8, "KeRNeL32.dll", "WriteFile", 5, 1);
    register_import_auto(0x00A1FCCC, "KeRNeL32.dll", "CreateDirectoryA", 2, 1);
    register_import_auto(0x00A1FCD0, "KeRNeL32.dll", "GetTempPathA", 2, 1);
    register_import_auto(0x00A1FCD4, "KeRNeL32.dll", "RemoveDirectoryA", 1, 1);
    register_import_auto(0x00A1FCD8, "KeRNeL32.dll", "GetStringTypeExA", 5, 1);
    register_import_auto(0x00A1FCDC, "KeRNeL32.dll", "IsBadStringPtrA", 2, 1);
    register_import_auto(0x00A1FCE0, "KeRNeL32.dll", "GetFileAttributesA", 1, 1);
    register_import_auto(0x00A1FCE4, "KeRNeL32.dll", "GetLocaleInfoA", 4, 1);
    register_import_auto(0x00A1FCE8, "KeRNeL32.dll", "GetProcAddress", 2, 1);
    register_import_auto(0x00A1FCEC, "KeRNeL32.dll", "MoveFileA", 2, 1);
    register_import_auto(0x00A1FCF0, "KeRNeL32.dll", "FreeLibrary", 1, 1);
    register_import_auto(0x00A1FCF4, "KeRNeL32.dll", "GetPrivateProfileStringA", 6, 1);
    register_import_auto(0x00A1FCF8, "KeRNeL32.dll", "LoadLibraryA", 1, 1);
    register_import_auto(0x00A1FCFC, "KeRNeL32.dll", "FindNextFileA", 2, 1);
    register_import_auto(0x00A1FD00, "KeRNeL32.dll", "FindFirstFileA", 2, 1);
    register_import_auto(0x00A1FD04, "KeRNeL32.dll", "FindClose", 1, 1);
    register_import_auto(0x00A1FD08, "KeRNeL32.dll", "GetFullPathNameA", 4, 1);
    register_import_auto(0x00A1FD0C, "KeRNeL32.dll", "WaitForSingleObject", 2, 1);
    register_import_auto(0x00A1FD10, "KeRNeL32.dll", "GetShortPathNameA", 3, 1);
    register_import_auto(0x00A1FD14, "KeRNeL32.dll", "ExitProcess", 1, 1);
    register_import_auto(0x00A1FD18, "KeRNeL32.dll", "GetCommandLineA", 0, 1);
    register_import_auto(0x00A1FD1C, "KeRNeL32.dll", "Sleep", 1, 1);
    register_import_auto(0x00A1FD20, "KeRNeL32.dll", "ReleaseMutex", 1, 1);
    register_import_auto(0x00A1FD24, "KeRNeL32.dll", "GetUserDefaultLangID", 0, 1);
    register_import_auto(0x00A1FD28, "KeRNeL32.dll", "CreateMutexA", 3, 1);
    register_import_auto(0x00A1FD2C, "KeRNeL32.dll", "GetFileSize", 2, 1);
    register_import_auto(0x00A1FD30, "KeRNeL32.dll", "OutputDebugStringA", 1, 1);
    register_import_auto(0x00A1FD34, "KeRNeL32.dll", "ReadFile", 5, 1);
    register_import_auto(0x00A1FD38, "KeRNeL32.dll", "GetFileTime", 4, 1);
    register_import_auto(0x00A1FD3C, "KeRNeL32.dll", "GetTickCount", 0, 1);
    register_import_auto(0x00A1FD40, "KeRNeL32.dll", "SetFilePointer", 4, 1);
    register_import_auto(0x00A1FD44, "KeRNeL32.dll", "GetLogicalDriveStringsA", 2, 1);
    register_import_auto(0x00A1FD48, "KeRNeL32.dll", "MultiByteToWideChar", 6, 1);
    register_import_auto(0x00A1FD4C, "KeRNeL32.dll", "GetDriveTypeA", 1, 1);
    register_import_auto(0x00A1FD50, "KeRNeL32.dll", "SetThreadPriority", 2, 1);
    register_import_auto(0x00A1FD54, "KeRNeL32.dll", "CreateThread", 6, 1);
    register_import_auto(0x00A1FD58, "KeRNeL32.dll", "ResumeThread", 1, 1);
    register_import_auto(0x00A1FD5C, "KeRNeL32.dll", "GetProcessAffinityMask", 3, 1);
    register_import_auto(0x00A1FD60, "KeRNeL32.dll", "GetCurrentProcess", 0, 1);
    register_import_auto(0x00A1FD64, "KeRNeL32.dll", "GlobalMemoryStatus", 1, 1);
    register_import_auto(0x00A1FD68, "KeRNeL32.dll", "QueryPerformanceCounter", 1, 1);
    register_import_auto(0x00A1FD6C, "KeRNeL32.dll", "QueryPerformanceFrequency", 1, 1);
    register_import_auto(0x00A1FD70, "KeRNeL32.dll", "GetThreadPriority", 1, 1);
    register_import_auto(0x00A1FD74, "KeRNeL32.dll", "GetCurrentThread", 0, 1);
    register_import_auto(0x00A1FD78, "KeRNeL32.dll", "GetCPInfo", 2, 1);
    register_import_auto(0x00A1FD7C, "KeRNeL32.dll", "LocalAlloc", 2, 1);
    register_import_auto(0x00A1FD80, "KeRNeL32.dll", "GetStartupInfoA", 1, 1);
    register_import_auto(0x00A1FD84, "KeRNeL32.dll", "GetModuleHandleA", 1, 1);
    register_import_auto(0x00A1FD88, "KeRNeL32.dll", "EnterCriticalSection", 1, 1);
    register_import_auto(0x00A1FD8C, "KeRNeL32.dll", "LeaveCriticalSection", 1, 1);
    register_import_auto(0x00A1FD90, "KeRNeL32.dll", "DeleteCriticalSection", 1, 1);
    register_import_auto(0x00A1FD94, "KeRNeL32.dll", "InitializeCriticalSection", 1, 1);
    register_import_auto(0x00A1FD98, "KeRNeL32.dll", "GetACP", 0, 1);
    register_import_auto(0x00A1FD9C, "KeRNeL32.dll", "CompareStringA", 6, 1);
    register_import_auto(0x00A1FDA0, "KeRNeL32.dll", "GetVersionExA", 1, 1);
    /* === MFC42.DLL (203 imports) === */
    register_import_ordinal(0x00A1FDA8, "MFC42.DLL", 3350, 4, 1);
    register_import_ordinal(0x00A1FDAC, "MFC42.DLL", 4303, 4, 1);
    register_import_ordinal(0x00A1FDB0, "MFC42.DLL", 4467, 4, 1);
    register_import_ordinal(0x00A1FDB4, "MFC42.DLL", 5103, 4, 1);
    register_import_ordinal(0x00A1FDB8, "MFC42.DLL", 5012, 4, 1);
    register_import_ordinal(0x00A1FDBC, "MFC42.DLL", 3403, 4, 1);
    register_import_ordinal(0x00A1FDC0, "MFC42.DLL", 2879, 4, 1);
    register_import_ordinal(0x00A1FDC4, "MFC42.DLL", 2878, 4, 1);
    register_import_ordinal(0x00A1FDC8, "MFC42.DLL", 975, 4, 1);
    register_import_ordinal(0x00A1FDCC, "MFC42.DLL", 4077, 4, 1);
    register_import_ordinal(0x00A1FDD0, "MFC42.DLL", 5472, 4, 1);
    register_import_ordinal(0x00A1FDD4, "MFC42.DLL", 4151, 4, 1);
    register_import_ordinal(0x00A1FDD8, "MFC42.DLL", 2649, 4, 1);
    register_import_ordinal(0x00A1FDDC, "MFC42.DLL", 1665, 4, 1);
    register_import_ordinal(0x00A1FDE0, "MFC42.DLL", 4436, 4, 1);
    register_import_ordinal(0x00A1FDE4, "MFC42.DLL", 5252, 4, 1);
    register_import_ordinal(0x00A1FDE8, "MFC42.DLL", 4427, 4, 1);
    register_import_ordinal(0x00A1FDEC, "MFC42.DLL", 4220, 4, 1);
    register_import_ordinal(0x00A1FDF0, "MFC42.DLL", 2584, 4, 1);
    register_import_ordinal(0x00A1FDF4, "MFC42.DLL", 3654, 4, 1);
    register_import_ordinal(0x00A1FDF8, "MFC42.DLL", 5237, 4, 1);
    register_import_ordinal(0x00A1FDFC, "MFC42.DLL", 1768, 4, 1);
    register_import_ordinal(0x00A1FE00, "MFC42.DLL", 2455, 4, 1);
    register_import_ordinal(0x00A1FE04, "MFC42.DLL", 5282, 4, 1);
    register_import_ordinal(0x00A1FE08, "MFC42.DLL", 1146, 4, 1);
    register_import_ordinal(0x00A1FE0C, "MFC42.DLL", 2438, 4, 1);
    register_import_ordinal(0x00A1FE10, "MFC42.DLL", 3663, 4, 1);
    register_import_ordinal(0x00A1FE14, "MFC42.DLL", 2379, 4, 1);
    register_import_ordinal(0x00A1FE18, "MFC42.DLL", 4457, 4, 1);
    register_import_ordinal(0x00A1FE1C, "MFC42.DLL", 2414, 4, 1);
    register_import_ordinal(0x00A1FE20, "MFC42.DLL", 4499, 4, 1);
    register_import_ordinal(0x00A1FE24, "MFC42.DLL", 6215, 4, 1);
    register_import_ordinal(0x00A1FE28, "MFC42.DLL", 2514, 4, 1);
    register_import_ordinal(0x00A1FE2C, "MFC42.DLL", 2575, 4, 1);
    register_import_ordinal(0x00A1FE30, "MFC42.DLL", 4396, 4, 1);
    register_import_ordinal(0x00A1FE34, "MFC42.DLL", 3574, 4, 1);
    register_import_ordinal(0x00A1FE38, "MFC42.DLL", 3721, 4, 1);
    register_import_ordinal(0x00A1FE3C, "MFC42.DLL", 795, 4, 1);
    register_import_ordinal(0x00A1FE40, "MFC42.DLL", 609, 4, 1);
    register_import_ordinal(0x00A1FE44, "MFC42.DLL", 2614, 4, 1);
    register_import_ordinal(0x00A1FE48, "MFC42.DLL", 6283, 4, 1);
    register_import_ordinal(0x00A1FE4C, "MFC42.DLL", 6282, 4, 1);
    register_import_ordinal(0x00A1FE50, "MFC42.DLL", 5710, 4, 1);
    register_import_ordinal(0x00A1FE54, "MFC42.DLL", 1644, 4, 1);
    register_import_ordinal(0x00A1FE58, "MFC42.DLL", 4129, 4, 1);
    register_import_ordinal(0x00A1FE5C, "MFC42.DLL", 3059, 4, 1);
    register_import_ordinal(0x00A1FE60, "MFC42.DLL", 5100, 4, 1);
    register_import_ordinal(0x00A1FE64, "MFC42.DLL", 6375, 4, 1);
    register_import_ordinal(0x00A1FE68, "MFC42.DLL", 3729, 4, 1);
    register_import_ordinal(0x00A1FE6C, "MFC42.DLL", 2818, 4, 1);
    register_import_ordinal(0x00A1FE70, "MFC42.DLL", 2152, 4, 1);
    register_import_ordinal(0x00A1FE74, "MFC42.DLL", 4406, 4, 1);
    register_import_ordinal(0x00A1FE78, "MFC42.DLL", 3394, 4, 1);
    register_import_ordinal(0x00A1FE7C, "MFC42.DLL", 2390, 4, 1);
    register_import_ordinal(0x00A1FE80, "MFC42.DLL", 3361, 4, 1);
    register_import_ordinal(0x00A1FE84, "MFC42.DLL", 2396, 4, 1);
    register_import_ordinal(0x00A1FE88, "MFC42.DLL", 3346, 4, 1);
    register_import_ordinal(0x00A1FE8C, "MFC42.DLL", 5300, 4, 1);
    register_import_ordinal(0x00A1FE90, "MFC42.DLL", 5302, 4, 1);
    register_import_ordinal(0x00A1FE94, "MFC42.DLL", 4079, 4, 1);
    register_import_ordinal(0x00A1FE98, "MFC42.DLL", 4698, 4, 1);
    register_import_ordinal(0x00A1FE9C, "MFC42.DLL", 5307, 4, 1);
    register_import_ordinal(0x00A1FEA0, "MFC42.DLL", 4622, 4, 1);
    register_import_ordinal(0x00A1FEA4, "MFC42.DLL", 3738, 4, 1);
    register_import_ordinal(0x00A1FEA8, "MFC42.DLL", 2621, 4, 1);
    register_import_ordinal(0x00A1FEAC, "MFC42.DLL", 1232, 4, 1);
    register_import_ordinal(0x00A1FEB0, "MFC42.DLL", 1168, 4, 1);
    register_import_ordinal(0x00A1FEB4, "MFC42.DLL", 2725, 4, 1);
    register_import_ordinal(0x00A1FEB8, "MFC42.DLL", 4274, 4, 1);
    register_import_ordinal(0x00A1FEBC, "MFC42.DLL", 5289, 4, 1);
    register_import_ordinal(0x00A1FEC0, "MFC42.DLL", 815, 4, 1);
    register_import_ordinal(0x00A1FEC4, "MFC42.DLL", 561, 4, 1);
    register_import_ordinal(0x00A1FEC8, "MFC42.DLL", 1842, 4, 1);
    register_import_ordinal(0x00A1FECC, "MFC42.DLL", 4242, 4, 1);
    register_import_ordinal(0x00A1FED0, "MFC42.DLL", 3571, 4, 1);
    register_import_ordinal(0x00A1FED4, "MFC42.DLL", 366, 4, 1);
    register_import_ordinal(0x00A1FED8, "MFC42.DLL", 3626, 4, 1);
    register_import_ordinal(0x00A1FEDC, "MFC42.DLL", 674, 4, 1);
    register_import_ordinal(0x00A1FEE0, "MFC42.DLL", 4413, 4, 1);
    register_import_ordinal(0x00A1FEE4, "MFC42.DLL", 755, 4, 1);
    register_import_ordinal(0x00A1FEE8, "MFC42.DLL", 470, 4, 1);
    register_import_ordinal(0x00A1FEEC, "MFC42.DLL", 5030, 4, 1);
    register_import_ordinal(0x00A1FEF0, "MFC42.DLL", 1641, 4, 1);
    register_import_ordinal(0x00A1FEF4, "MFC42.DLL", 4337, 4, 1);
    register_import_ordinal(0x00A1FEF8, "MFC42.DLL", 6376, 4, 1);
    register_import_ordinal(0x00A1FEFC, "MFC42.DLL", 2055, 4, 1);
    register_import_ordinal(0x00A1FF00, "MFC42.DLL", 2648, 4, 1);
    register_import_ordinal(0x00A1FF04, "MFC42.DLL", 4441, 4, 1);
    register_import_ordinal(0x00A1FF08, "MFC42.DLL", 4837, 4, 1);
    register_import_ordinal(0x00A1FF0C, "MFC42.DLL", 3798, 4, 1);
    register_import_ordinal(0x00A1FF10, "MFC42.DLL", 5280, 4, 1);
    register_import_ordinal(0x00A1FF14, "MFC42.DLL", 4353, 4, 1);
    register_import_ordinal(0x00A1FF18, "MFC42.DLL", 6374, 4, 1);
    register_import_ordinal(0x00A1FF1C, "MFC42.DLL", 5163, 4, 1);
    register_import_ordinal(0x00A1FF20, "MFC42.DLL", 2723, 4, 1);
    register_import_ordinal(0x00A1FF24, "MFC42.DLL", 922, 4, 1);
    register_import_ordinal(0x00A1FF28, "MFC42.DLL", 926, 4, 1);
    register_import_ordinal(0x00A1FF2C, "MFC42.DLL", 2086, 4, 1);
    register_import_ordinal(0x00A1FF30, "MFC42.DLL", 2385, 4, 1);
    register_import_ordinal(0x00A1FF34, "MFC42.DLL", 5241, 4, 1);
    register_import_ordinal(0x00A1FF38, "MFC42.DLL", 4407, 4, 1);
    register_import_ordinal(0x00A1FF3C, "MFC42.DLL", 1775, 4, 1);
    register_import_ordinal(0x00A1FF40, "MFC42.DLL", 4078, 4, 1);
    register_import_ordinal(0x00A1FF44, "MFC42.DLL", 6052, 4, 1);
    register_import_ordinal(0x00A1FF48, "MFC42.DLL", 4710, 4, 1);
    register_import_ordinal(0x00A1FF4C, "MFC42.DLL", 4486, 4, 1);
    register_import_ordinal(0x00A1FF50, "MFC42.DLL", 2554, 4, 1);
    register_import_ordinal(0x00A1FF54, "MFC42.DLL", 2512, 4, 1);
    register_import_ordinal(0x00A1FF58, "MFC42.DLL", 1576, 4, 1);
    register_import_ordinal(0x00A1FF5C, "MFC42.DLL", 4998, 4, 1);
    register_import_ordinal(0x00A1FF60, "MFC42.DLL", 2587, 4, 1);
    register_import_ordinal(0x00A1FF64, "MFC42.DLL", 4424, 4, 1);
    register_import_ordinal(0x00A1FF68, "MFC42.DLL", 4853, 4, 1);
    register_import_ordinal(0x00A1FF6C, "MFC42.DLL", 2642, 4, 1);
    register_import_ordinal(0x00A1FF70, "MFC42.DLL", 2362, 4, 1);
    register_import_ordinal(0x00A1FF74, "MFC42.DLL", 2301, 4, 1);
    register_import_ordinal(0x00A1FF78, "MFC42.DLL", 3874, 4, 1);
    register_import_ordinal(0x00A1FF7C, "MFC42.DLL", 6605, 4, 1);
    register_import_ordinal(0x00A1FF80, "MFC42.DLL", 4284, 4, 1);
    register_import_ordinal(0x00A1FF84, "MFC42.DLL", 3402, 4, 1);
    register_import_ordinal(0x00A1FF88, "MFC42.DLL", 4299, 4, 1);
    register_import_ordinal(0x00A1FF8C, "MFC42.DLL", 2864, 4, 1);
    register_import_ordinal(0x00A1FF90, "MFC42.DLL", 6880, 4, 1);
    register_import_ordinal(0x00A1FF94, "MFC42.DLL", 2915, 4, 1);
    register_import_ordinal(0x00A1FF98, "MFC42.DLL", 939, 4, 1);
    register_import_ordinal(0x00A1FF9C, "MFC42.DLL", 3803, 4, 1);
    register_import_ordinal(0x00A1FFA0, "MFC42.DLL", 2645, 4, 1);
    register_import_ordinal(0x00A1FFA4, "MFC42.DLL", 6199, 4, 1);
    register_import_ordinal(0x00A1FFA8, "MFC42.DLL", 924, 4, 1);
    register_import_ordinal(0x00A1FFAC, "MFC42.DLL", 5731, 4, 1);
    register_import_ordinal(0x00A1FFB0, "MFC42.DLL", 2581, 4, 1);
    register_import_ordinal(0x00A1FFB4, "MFC42.DLL", 4376, 4, 1);
    register_import_ordinal(0x00A1FFB8, "MFC42.DLL", 3639, 4, 1);
    register_import_ordinal(0x00A1FFBC, "MFC42.DLL", 4401, 4, 1);
    register_import_ordinal(0x00A1FFC0, "MFC42.DLL", 2413, 4, 1);
    register_import_ordinal(0x00A1FFC4, "MFC42.DLL", 4219, 4, 1);
    register_import_ordinal(0x00A1FFC8, "MFC42.DLL", 2024, 4, 1);
    register_import_ordinal(0x00A1FFCC, "MFC42.DLL", 2737, 4, 1);
    register_import_ordinal(0x00A1FFD0, "MFC42.DLL", 6366, 4, 1);
    register_import_ordinal(0x00A1FFD4, "MFC42.DLL", 1771, 4, 1);
    register_import_ordinal(0x00A1FFD8, "MFC42.DLL", 3873, 4, 1);
    register_import_ordinal(0x00A1FFDC, "MFC42.DLL", 2370, 4, 1);
    register_import_ordinal(0x00A1FFE0, "MFC42.DLL", 6453, 4, 1);
    register_import_ordinal(0x00A1FFE4, "MFC42.DLL", 6334, 4, 1);
    register_import_ordinal(0x00A1FFE8, "MFC42.DLL", 4224, 4, 1);
    register_import_ordinal(0x00A1FFEC, "MFC42.DLL", 5981, 4, 1);
    register_import_ordinal(0x00A1FFF0, "MFC42.DLL", 2366, 4, 1);
    register_import_ordinal(0x00A1FFF4, "MFC42.DLL", 4234, 4, 1);
    register_import_ordinal(0x00A1FFF8, "MFC42.DLL", 2302, 4, 1);
    register_import_ordinal(0x00A1FFFC, "MFC42.DLL", 324, 4, 1);
    register_import_ordinal(0x00A20000, "MFC42.DLL", 2293, 4, 1);
    register_import_ordinal(0x00A20004, "MFC42.DLL", 616, 4, 1);
    register_import_ordinal(0x00A20008, "MFC42.DLL", 4425, 4, 1);
    register_import_ordinal(0x00A2000C, "MFC42.DLL", 567, 4, 1);
    register_import_ordinal(0x00A20010, "MFC42.DLL", 3597, 4, 1);
    register_import_ordinal(0x00A20014, "MFC42.DLL", 3079, 4, 1);
    register_import_ordinal(0x00A20018, "MFC42.DLL", 4627, 4, 1);
    register_import_ordinal(0x00A2001C, "MFC42.DLL", 4080, 4, 1);
    register_import_ordinal(0x00A20020, "MFC42.DLL", 3830, 4, 1);
    register_import_ordinal(0x00A20024, "MFC42.DLL", 3825, 4, 1);
    register_import_ordinal(0x00A20028, "MFC42.DLL", 3831, 4, 1);
    register_import_ordinal(0x00A2002C, "MFC42.DLL", 3922, 4, 1);
    register_import_ordinal(0x00A20030, "MFC42.DLL", 2976, 4, 1);
    register_import_ordinal(0x00A20034, "MFC42.DLL", 5265, 4, 1);
    register_import_ordinal(0x00A20038, "MFC42.DLL", 3081, 4, 1);
    register_import_ordinal(0x00A2003C, "MFC42.DLL", 2985, 4, 1);
    register_import_ordinal(0x00A20040, "MFC42.DLL", 3262, 4, 1);
    register_import_ordinal(0x00A20044, "MFC42.DLL", 3136, 4, 1);
    register_import_ordinal(0x00A20048, "MFC42.DLL", 4465, 4, 1);
    register_import_ordinal(0x00A2004C, "MFC42.DLL", 3259, 4, 1);
    register_import_ordinal(0x00A20050, "MFC42.DLL", 3147, 4, 1);
    register_import_ordinal(0x00A20054, "MFC42.DLL", 2982, 4, 1);
    register_import_ordinal(0x00A20058, "MFC42.DLL", 5277, 4, 1);
    register_import_ordinal(0x00A2005C, "MFC42.DLL", 2124, 4, 1);
    register_import_ordinal(0x00A20060, "MFC42.DLL", 2446, 4, 1);
    register_import_ordinal(0x00A20064, "MFC42.DLL", 5261, 4, 1);
    register_import_ordinal(0x00A20068, "MFC42.DLL", 1727, 4, 1);
    register_import_ordinal(0x00A2006C, "MFC42.DLL", 5065, 4, 1);
    register_import_ordinal(0x00A20070, "MFC42.DLL", 3749, 4, 1);
    register_import_ordinal(0x00A20074, "MFC42.DLL", 1089, 4, 1);
    register_import_ordinal(0x00A20078, "MFC42.DLL", 5199, 4, 1);
    register_import_ordinal(0x00A2007C, "MFC42.DLL", 2764, 4, 1);
    register_import_ordinal(0x00A20080, "MFC42.DLL", 3582, 4, 1);
    register_import_ordinal(0x00A20084, "MFC42.DLL", 823, 4, 1);
    register_import_ordinal(0x00A20088, "MFC42.DLL", 800, 4, 1);
    register_import_ordinal(0x00A2008C, "MFC42.DLL", 825, 4, 1);
    register_import_ordinal(0x00A20090, "MFC42.DLL", 860, 4, 1);
    register_import_ordinal(0x00A20094, "MFC42.DLL", 540, 4, 1);
    register_import_ordinal(0x00A20098, "MFC42.DLL", 537, 4, 1);
    register_import_ordinal(0x00A2009C, "MFC42.DLL", 941, 4, 1);
    register_import_ordinal(0x00A200A0, "MFC42.DLL", 535, 4, 1);
    register_import_ordinal(0x00A200A4, "MFC42.DLL", 858, 4, 1);
    register_import_ordinal(0x00A200A8, "MFC42.DLL", 804, 4, 1);
    register_import_ordinal(0x00A200AC, "MFC42.DLL", 692, 4, 1);
    register_import_ordinal(0x00A200B0, "MFC42.DLL", 641, 4, 1);
    register_import_ordinal(0x00A200B4, "MFC42.DLL", 2023, 4, 1);
    register_import_ordinal(0x00A200B8, "MFC42.DLL", 4218, 4, 1);
    register_import_ordinal(0x00A200BC, "MFC42.DLL", 2411, 4, 1);
    register_import_ordinal(0x00A200C0, "MFC42.DLL", 6055, 4, 1);
    register_import_ordinal(0x00A200C4, "MFC42.DLL", 1776, 4, 1);
    register_import_ordinal(0x00A200C8, "MFC42.DLL", 2578, 4, 1);
    register_import_ordinal(0x00A200CC, "MFC42.DLL", 5290, 4, 1);
    register_import_ordinal(0x00A200D0, "MFC42.DLL", 4398, 4, 1);
    /* === MSACM32.dll (8 imports) === */
    register_import_auto(0x00A200D8, "MSACM32.dll", "acmStreamPrepareHeader", 3, 1);
    register_import_auto(0x00A200DC, "MSACM32.dll", "acmStreamOpen", 8, 1);
    register_import_auto(0x00A200E0, "MSACM32.dll", "acmStreamUnprepareHeader", 3, 1);
    register_import_auto(0x00A200E4, "MSACM32.dll", "acmStreamClose", 2, 1);
    register_import_auto(0x00A200E8, "MSACM32.dll", "acmStreamSize", 4, 1);
    register_import_auto(0x00A200EC, "MSACM32.dll", "acmMetrics", 3, 1);
    register_import_auto(0x00A200F0, "MSACM32.dll", "acmStreamConvert", 3, 1);
    register_import_auto(0x00A200F4, "MSACM32.dll", "acmFormatSuggest", 5, 1);
    /* === MSVCP60.dll (33 imports) === */
    register_import_auto(0x00A200FC, "MSVCP60.dll", "?_Eos@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXI@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20100, "MSVCP60.dll", "?_Tidy@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEX_N@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20104, "MSVCP60.dll", "?_Xlen@std@@YAXXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20108, "MSVCP60.dll", "?max_size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QBEIXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2010C, "MSVCP60.dll", "?_Grow@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAE_NI_N@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20110, "MSVCP60.dll", "?_C@?1??_Nullstr@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@CAPBDXZ@4DB", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20114, "MSVCP60.dll", "?erase@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@II@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20118, "MSVCP60.dll", "?npos@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@2IB", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2011C, "MSVCP60.dll", "??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20120, "MSVCP60.dll", "??0Init@ios_base@std@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20124, "MSVCP60.dll", "??1Init@ios_base@std@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20128, "MSVCP60.dll", "??0_Winit@std@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2012C, "MSVCP60.dll", "??1_Winit@std@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20130, "MSVCP60.dll", "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBDI@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20134, "MSVCP60.dll", "?_Xran@std@@YAXXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20138, "MSVCP60.dll", "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@ABV12@II@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2013C, "MSVCP60.dll", "?_Split@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20140, "MSVCP60.dll", "??8std@@YA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@0@PBD@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20144, "MSVCP60.dll", "?_Refcnt@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEAAEPBD@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20148, "MSVCP60.dll", "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@ABV?$allocator@D@1@@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2014C, "MSVCP60.dll", "??_F?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEXXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20150, "MSVCP60.dll", "??Hstd@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@0@ABV10@PBD@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20154, "MSVCP60.dll", "?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QBEPBDXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20158, "MSVCP60.dll", "?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBDI@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2015C, "MSVCP60.dll", "??1_Lockit@std@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20160, "MSVCP60.dll", "??0_Lockit@std@@QAE@XZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20164, "MSVCP60.dll", "?insert@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@IPBDI@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20168, "MSVCP60.dll", "??9std@@YA_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@0@PBD@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2016C, "MSVCP60.dll", "??Hstd@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@0@ABV10@D@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20170, "MSVCP60.dll", "?assign@?$char_traits@D@std@@SAXAADABD@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20174, "MSVCP60.dll", "?_Nullstr@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@CAPBDXZ", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A20178, "MSVCP60.dll", "??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV01@PBD@Z", 2, 2); /* thiscall, TODO: nargs */
    register_import_auto(0x00A2017C, "MSVCP60.dll", "?_Copy@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXI@Z", 2, 2); /* thiscall, TODO: nargs */
    /* === MSVCRT.dll (124 imports) === */
    register_import_auto(0x00A20184, "MSVCRT.dll", "_fullpath", 3, 0);
    register_import_auto(0x00A20188, "MSVCRT.dll", "_chmod", 2, 0);
    register_import_auto(0x00A2018C, "MSVCRT.dll", "rename", 2, 0);
    register_import_auto(0x00A20190, "MSVCRT.dll", "strstr", 2, 0);
    register_import_auto(0x00A20194, "MSVCRT.dll", "fflush", 1, 0);
    register_import_auto(0x00A20198, "MSVCRT.dll", "_CIasin", 0, 0);
    register_import_auto(0x00A2019C, "MSVCRT.dll", "_beginthreadex", 6, 0);
    register_import_auto(0x00A201A0, "MSVCRT.dll", "isupper", 1, 0);
    register_import_auto(0x00A201A4, "MSVCRT.dll", "isspace", 1, 0);
    register_import_auto(0x00A201A8, "MSVCRT.dll", "strtok", 2, 0);
    /* 0x00A201AC _iob -- custom bridge (registered separately) */
    register_import_auto(0x00A201B0, "MSVCRT.dll", "time", 1, 0);
    register_import_auto(0x00A201B4, "MSVCRT.dll", "calloc", 2, 0);
    register_import_auto(0x00A201B8, "MSVCRT.dll", "_stat", 2, 0);
    register_import_auto(0x00A201BC, "MSVCRT.dll", "atof", 1, 0);
    register_import_auto(0x00A201C0, "MSVCRT.dll", "memmove", 3, 0);
    register_import_auto(0x00A201C4, "MSVCRT.dll", "toupper", 1, 0);
    register_import_auto(0x00A201C8, "MSVCRT.dll", "strrchr", 2, 0);
    register_import_auto(0x00A201CC, "MSVCRT.dll", "tolower", 1, 0);
    register_import_auto(0x00A201D0, "MSVCRT.dll", "fprintf", 3, 0);
    register_import_auto(0x00A201D4, "MSVCRT.dll", "_access", 2, 0);
    register_import_auto(0x00A201D8, "MSVCRT.dll", "srand", 1, 0);
    register_import_auto(0x00A201DC, "MSVCRT.dll", "floor", 2, 0);
    register_import_auto(0x00A201E0, "MSVCRT.dll", "_rmtmp", 0, 0);
    register_import_auto(0x00A201E4, "MSVCRT.dll", "_vsnprintf", 4, 0);
    register_import_auto(0x00A201E8, "MSVCRT.dll", "wctomb", 2, 0);
    register_import_auto(0x00A201EC, "MSVCRT.dll", "_isnan", 2, 0);
    register_import_auto(0x00A201F0, "MSVCRT.dll", "_CIfmod", 0, 0);
    register_import_auto(0x00A201F4, "MSVCRT.dll", "_splitpath", 5, 0);
    register_import_auto(0x00A201F8, "MSVCRT.dll", "fread", 4, 0);
    register_import_auto(0x00A201FC, "MSVCRT.dll", "exit", 1, 0);
    register_import_auto(0x00A20200, "MSVCRT.dll", "malloc", 1, 0);
    register_import_auto(0x00A20204, "MSVCRT.dll", "free", 1, 0);
    register_import_auto(0x00A20208, "MSVCRT.dll", "strncpy", 3, 0);
    /* 0x00A2020C _purecall -- custom bridge (registered separately) */
    register_import_auto(0x00A20210, "MSVCRT.dll", "sprintf", 3, 0);
    register_import_auto(0x00A20214, "MSVCRT.dll", "_stricmp", 2, 0);
    register_import_auto(0x00A20218, "MSVCRT.dll", "_strdup", 1, 0);
    register_import_auto(0x00A2021C, "MSVCRT.dll", "fopen", 2, 0);
    register_import_auto(0x00A20220, "MSVCRT.dll", "fgets", 3, 0);
    register_import_auto(0x00A20224, "MSVCRT.dll", "vsprintf", 3, 0);
    register_import_auto(0x00A20228, "MSVCRT.dll", "_exit", 1, 0);
    register_import_auto(0x00A2022C, "MSVCRT.dll", "isleadbyte", 1, 0);
    register_import_auto(0x00A20230, "MSVCRT.dll", "_mbscpy", 2, 0);
    register_import_auto(0x00A20234, "MSVCRT.dll", "_mbstrlen", 1, 0);
    register_import_auto(0x00A20238, "MSVCRT.dll", "setlocale", 2, 0);
    register_import_auto(0x00A2023C, "MSVCRT.dll", "isprint", 1, 0);
    register_import_auto(0x00A20240, "MSVCRT.dll", "_controlfp", 2, 0);
    register_import_auto(0x00A20244, "MSVCRT.dll", "fclose", 1, 0);
    register_import_auto(0x00A20248, "MSVCRT.dll", "atoi", 1, 0);
    register_import_auto(0x00A2024C, "MSVCRT.dll", "sscanf", 3, 0);
    register_import_auto(0x00A20250, "MSVCRT.dll", "_itoa", 3, 0);
    register_import_auto(0x00A20254, "MSVCRT.dll", "_strnicmp", 3, 0);
    register_import_auto(0x00A20258, "MSVCRT.dll", "strchr", 2, 0);
    register_import_auto(0x00A2025C, "MSVCRT.dll", "isdigit", 1, 0);
    register_import_auto(0x00A20260, "MSVCRT.dll", "atol", 1, 0);
    register_import_auto(0x00A20264, "MSVCRT.dll", "ceil", 2, 0);
    register_import_auto(0x00A20268, "MSVCRT.dll", "fseek", 3, 0);
    register_import_auto(0x00A2026C, "MSVCRT.dll", "ftell", 1, 0);
    register_import_auto(0x00A20270, "MSVCRT.dll", "rewind", 1, 0);
    register_import_auto(0x00A20274, "MSVCRT.dll", "fscanf", 3, 0);
    register_import_auto(0x00A20278, "MSVCRT.dll", "strncat", 3, 0);
    register_import_auto(0x00A2027C, "MSVCRT.dll", "_copysign", 4, 0);
    /* 0x00A20280 _pctype -- custom bridge (registered separately) */
    register_import_auto(0x00A20284, "MSVCRT.dll", "_isctype", 2, 0);
    /* 0x00A20288 __mb_cur_max -- custom bridge (registered separately) */
    register_import_auto(0x00A2028C, "MSVCRT.dll", "_snprintf", 4, 0);
    register_import_auto(0x00A20290, "MSVCRT.dll", "strtod", 2, 0);
    register_import_auto(0x00A20294, "MSVCRT.dll", "strtol", 3, 0);
    register_import_auto(0x00A20298, "MSVCRT.dll", "ctime", 1, 0);
    register_import_auto(0x00A2029C, "MSVCRT.dll", "freopen", 3, 0);
    register_import_auto(0x00A202A0, "MSVCRT.dll", "_findclose", 1, 0);
    register_import_auto(0x00A202A4, "MSVCRT.dll", "_findnext", 2, 0);
    register_import_auto(0x00A202A8, "MSVCRT.dll", "_findfirst", 2, 0);
    register_import_auto(0x00A202AC, "MSVCRT.dll", "fgetc", 1, 0);
    register_import_auto(0x00A202B0, "MSVCRT.dll", "strpbrk", 2, 0);
    register_import_auto(0x00A202B4, "MSVCRT.dll", "iswspace", 1, 0);
    register_import_auto(0x00A202B8, "MSVCRT.dll", "difftime", 2, 0);
    register_import_auto(0x00A202BC, "MSVCRT.dll", "strlen", 1, 0);
    register_import_auto(0x00A202C0, "MSVCRT.dll", "strcmp", 2, 0);
    register_import_auto(0x00A202C4, "MSVCRT.dll", "memcpy", 3, 0);
    register_import_auto(0x00A202C8, "MSVCRT.dll", "memset", 3, 0);
    register_import_auto(0x00A202CC, "MSVCRT.dll", "abs", 1, 0);
    register_import_auto(0x00A202D0, "MSVCRT.dll", "tmpfile", 0, 0);
    register_import_auto(0x00A202D4, "MSVCRT.dll", "_mkdir", 1, 0);
    register_import_auto(0x00A202D8, "MSVCRT.dll", "fwrite", 4, 0);
    /* 0x00A202DC _errno -- custom bridge (registered separately) */
    register_import_auto(0x00A202E0, "MSVCRT.dll", "__RTtypeid", 1, 0);
    /* 0x00A202E4 __p__commode -- custom bridge (registered separately) */
    register_import_auto(0x00A202E8, "MSVCRT.dll", "_ftol", 0, 0);
    register_import_auto(0x00A202EC, "MSVCRT.dll", "qsort", 4, 0);
    /* 0x00A202F0 __set_app_type -- custom bridge (registered separately) */
    /* 0x00A202F4 __p__fmode -- custom bridge (registered separately) */
    /* 0x00A202F8 _initterm -- custom bridge (registered separately) */
    /* 0x00A202FC _adjust_fdiv -- custom bridge (registered separately) */
    /* 0x00A20300 __setusermatherr -- custom bridge (registered separately) */
    /* 0x00A20304 _XcptFilter -- custom bridge (registered separately) */
    /* 0x00A20308 __getmainargs -- custom bridge (registered separately) */
    /* 0x00A2030C _acmdln -- custom bridge (registered separately) */
    /* 0x00A20310 _except_handler3 -- custom bridge (registered separately) */
    register_import_auto(0x00A20314, "MSVCRT.dll", "??1type_info@@UAE@XZ", 1, 0);
    register_import_auto(0x00A20318, "MSVCRT.dll", "?terminate@@YAXXZ", 0, 0);
    register_import_auto(0x00A2031C, "MSVCRT.dll", "abort", 0, 0);
    register_import_auto(0x00A20320, "MSVCRT.dll", "_onexit", 1, 0);
    register_import_auto(0x00A20324, "MSVCRT.dll", "__dllonexit", 3, 0);
    register_import_auto(0x00A20328, "MSVCRT.dll", "_mbsinc", 1, 0);
    register_import_auto(0x00A2032C, "MSVCRT.dll", "_mbsninc", 2, 0);
    register_import_auto(0x00A20330, "MSVCRT.dll", "_mbsnextc", 1, 0);
    register_import_auto(0x00A20334, "MSVCRT.dll", "??8type_info@@QBEHABV0@@Z", 2, 0);
    register_import_auto(0x00A20338, "MSVCRT.dll", "realloc", 2, 0);
    register_import_auto(0x00A2033C, "MSVCRT.dll", "__RTDynamicCast", 5, 0);
    /* 0x00A20340 __CxxFrameHandler -- custom bridge (registered separately) */
    register_import_auto(0x00A20344, "MSVCRT.dll", "printf", 2, 0);
    register_import_auto(0x00A20348, "MSVCRT.dll", "strncmp", 3, 0);
    register_import_auto(0x00A2034C, "MSVCRT.dll", "_CIacos", 0, 0);
    register_import_auto(0x00A20350, "MSVCRT.dll", "rand", 0, 0);
    register_import_auto(0x00A20354, "MSVCRT.dll", "remove", 1, 0);
    register_import_auto(0x00A20358, "MSVCRT.dll", "_CIpow", 0, 0);
    /* 0x00A2035C _HUGE -- custom bridge (registered separately) */
    register_import_auto(0x00A20360, "MSVCRT.dll", "_strcmpi", 2, 0);
    register_import_auto(0x00A20364, "MSVCRT.dll", "_strupr", 1, 0);
    register_import_auto(0x00A20368, "MSVCRT.dll", "_strlwr", 1, 0);
    register_import_auto(0x00A2036C, "MSVCRT.dll", "_swab", 3, 0);
    register_import_auto(0x00A20370, "MSVCRT.dll", "_setmbcp", 1, 0);
    /* === MSVFW32.dll (4 imports) === */
    register_import_auto(0x00A20378, "MSVFW32.dll", "ICDecompress", 8, 1);
    register_import_auto(0x00A2037C, "MSVFW32.dll", "ICLocate", 5, 1);
    register_import_auto(0x00A20380, "MSVFW32.dll", "ICClose", 1, 1);
    register_import_auto(0x00A20384, "MSVFW32.dll", "ICSendMessage", 4, 1);
    /* === SHELL32.dll (3 imports) === */
    register_import_auto(0x00A2038C, "SHELL32.dll", "SHGetPathFromIDListA", 2, 1);
    register_import_auto(0x00A20390, "SHELL32.dll", "ShellExecuteA", 6, 1);
    register_import_auto(0x00A20394, "SHELL32.dll", "SHGetSpecialFolderLocation", 3, 1);
    /* === USER32.dll (62 imports) === */
    register_import_auto(0x00A2039C, "USER32.dll", "RegisterWindowMessageA", 1, 1);
    register_import_auto(0x00A203A0, "USER32.dll", "LoadBitmapA", 2, 1);
    register_import_auto(0x00A203A4, "USER32.dll", "MsgWaitForMultipleObjects", 5, 1);
    register_import_auto(0x00A203A8, "USER32.dll", "SetRect", 5, 1);
    register_import_auto(0x00A203AC, "USER32.dll", "IsCharAlphaNumericA", 1, 1);
    register_import_auto(0x00A203B0, "USER32.dll", "PostQuitMessage", 1, 1);
    register_import_auto(0x00A203B4, "USER32.dll", "AdjustWindowRectEx", 4, 1);
    register_import_auto(0x00A203B8, "USER32.dll", "GetMenu", 1, 1);
    register_import_auto(0x00A203BC, "USER32.dll", "SystemParametersInfoA", 4, 1);
    register_import_auto(0x00A203C0, "USER32.dll", "GetWindowRect", 2, 1);
    register_import_auto(0x00A203C4, "USER32.dll", "ShowWindow", 2, 1);
    register_import_auto(0x00A203C8, "USER32.dll", "OpenIcon", 1, 1);
    register_import_auto(0x00A203CC, "USER32.dll", "EqualRect", 2, 1);
    register_import_auto(0x00A203D0, "USER32.dll", "SetWindowPos", 7, 1);
    register_import_auto(0x00A203D4, "USER32.dll", "ReleaseDC", 2, 1);
    register_import_auto(0x00A203D8, "USER32.dll", "DrawTextExA", 6, 1);
    register_import_auto(0x00A203DC, "USER32.dll", "IntersectRect", 3, 1);
    register_import_auto(0x00A203E0, "USER32.dll", "PeekMessageA", 5, 1);
    register_import_auto(0x00A203E4, "USER32.dll", "GetKeyboardType", 1, 1);
    register_import_auto(0x00A203E8, "USER32.dll", "ClientToScreen", 2, 1);
    register_import_auto(0x00A203EC, "USER32.dll", "GetKeyNameTextA", 3, 1);
    register_import_auto(0x00A203F0, "USER32.dll", "GetKeyboardState", 1, 1);
    register_import_auto(0x00A203F4, "USER32.dll", "MapVirtualKeyA", 2, 1);
    register_import_auto(0x00A203F8, "USER32.dll", "ToAscii", 5, 1);
    register_import_auto(0x00A203FC, "USER32.dll", "MessageBeep", 1, 1);
    register_import_auto(0x00A20400, "USER32.dll", "MessageBoxExA", 5, 1);
    register_import_auto(0x00A20404, "USER32.dll", "UnregisterClassA", 2, 1);
    register_import_auto(0x00A20408, "USER32.dll", "GetLastActivePopup", 1, 1);
    register_import_auto(0x00A2040C, "USER32.dll", "IsIconic", 1, 1);
    register_import_auto(0x00A20410, "USER32.dll", "CharNextA", 1, 1);
    register_import_auto(0x00A20414, "USER32.dll", "GetClientRect", 2, 1);
    register_import_auto(0x00A20418, "USER32.dll", "GetDC", 1, 1);
    register_import_auto(0x00A2041C, "USER32.dll", "TranslateMessage", 1, 1);
    register_import_auto(0x00A20420, "USER32.dll", "OffsetRect", 3, 1);
    register_import_auto(0x00A20424, "USER32.dll", "GetKeyboardLayout", 1, 1);
    register_import_auto(0x00A20428, "USER32.dll", "DispatchMessageA", 1, 1);
    register_import_auto(0x00A2042C, "USER32.dll", "SetFocus", 1, 1);
    register_import_auto(0x00A20430, "USER32.dll", "CharPrevA", 2, 1);
    register_import_auto(0x00A20434, "USER32.dll", "SetCursorPos", 2, 1);
    register_import_auto(0x00A20438, "USER32.dll", "GetSystemMetrics", 1, 1);
    register_import_auto(0x00A2043C, "USER32.dll", "LoadMenuA", 2, 1);
    register_import_auto(0x00A20440, "USER32.dll", "SetWindowLongA", 3, 1);
    register_import_auto(0x00A20444, "USER32.dll", "PostMessageA", 4, 1);
    register_import_auto(0x00A20448, "USER32.dll", "FindWindowA", 2, 1);
    register_import_auto(0x00A2044C, "USER32.dll", "SetForegroundWindow", 1, 1);
    register_import_auto(0x00A20450, "USER32.dll", "DefWindowProcA", 4, 1);
    register_import_auto(0x00A20454, "USER32.dll", "LoadIconA", 2, 1);
    register_import_auto(0x00A20458, "USER32.dll", "LoadCursorA", 2, 1);
    register_import_auto(0x00A2045C, "USER32.dll", "UpdateWindow", 1, 1);
    register_import_auto(0x00A20460, "USER32.dll", "ClipCursor", 1, 1);
    register_import_auto(0x00A20464, "USER32.dll", "ShowCursor", 1, 1);
    register_import_auto(0x00A20468, "USER32.dll", "RemoveMenu", 3, 1);
    register_import_auto(0x00A2046C, "USER32.dll", "GetWindowLongA", 2, 1);
    register_import_auto(0x00A20470, "USER32.dll", "GetParent", 1, 1);
    register_import_auto(0x00A20474, "USER32.dll", "MessageBoxA", 4, 1);
    register_import_auto(0x00A20478, "USER32.dll", "LoadStringA", 4, 1);
    register_import_auto(0x00A2047C, "USER32.dll", "CheckMenuItem", 3, 1);
    register_import_auto(0x00A20480, "USER32.dll", "InvalidateRect", 3, 1);
    register_import_auto(0x00A20484, "USER32.dll", "SetMenu", 2, 1);
    register_import_auto(0x00A20488, "USER32.dll", "SendMessageA", 4, 1);
    register_import_auto(0x00A2048C, "USER32.dll", "GetKeyState", 1, 1);
    register_import_auto(0x00A20490, "USER32.dll", "EnableWindow", 2, 1);
    /* === WINMM.dll (14 imports) === */
    register_import_auto(0x00A20498, "WINMM.dll", "mixerGetLineInfoA", 3, 1);
    register_import_auto(0x00A2049C, "WINMM.dll", "mixerOpen", 5, 1);
    register_import_auto(0x00A204A0, "WINMM.dll", "mciGetErrorStringA", 3, 1);
    register_import_auto(0x00A204A4, "WINMM.dll", "mixerGetLineControlsA", 3, 1);
    register_import_auto(0x00A204A8, "WINMM.dll", "mixerClose", 1, 1);
    register_import_auto(0x00A204AC, "WINMM.dll", "auxSetVolume", 2, 1);
    register_import_auto(0x00A204B0, "WINMM.dll", "auxGetVolume", 2, 1);
    register_import_auto(0x00A204B4, "WINMM.dll", "mciSendCommandA", 4, 1);
    register_import_auto(0x00A204B8, "WINMM.dll", "auxGetNumDevs", 0, 1);
    register_import_auto(0x00A204BC, "WINMM.dll", "auxGetDevCapsA", 3, 1);
    register_import_auto(0x00A204C0, "WINMM.dll", "mixerSetControlDetails", 3, 1);
    register_import_auto(0x00A204C4, "WINMM.dll", "mixerGetControlDetailsA", 3, 1);
    register_import_auto(0x00A204C8, "WINMM.dll", "mixerGetNumDevs", 0, 1);
    register_import_auto(0x00A204CC, "WINMM.dll", "timeGetTime", 0, 1);
    /* === comdlg32.dll (2 imports) === */
    register_import_auto(0x00A204D4, "comdlg32.dll", "GetSaveFileNameA", 1, 1);
    register_import_auto(0x00A204D8, "comdlg32.dll", "GetOpenFileNameA", 1, 1);
    /* === ole32.dll (3 imports) === */
    register_import_auto(0x00A204E0, "ole32.dll", "CoInitialize", 1, 1);
    register_import_auto(0x00A204E4, "ole32.dll", "CoCreateInstance", 5, 1);
    register_import_auto(0x00A204E8, "ole32.dll", "CoUninitialize", 0, 1);
    /* === zTiff.dll (5 imports) === */
    register_import_auto(0x00A204F0, "zTiff.dll", "TIFFNumberOfStrips", 0, 1); /* TODO: nargs */
    register_import_auto(0x00A204F4, "zTiff.dll", "TIFFOpen", 0, 1); /* TODO: nargs */
    register_import_auto(0x00A204F8, "zTiff.dll", "TIFFClose", 0, 1); /* TODO: nargs */
    register_import_auto(0x00A204FC, "zTiff.dll", "TIFFGetField", 0, 1); /* TODO: nargs */
    register_import_auto(0x00A20500, "zTiff.dll", "TIFFReadEncodedStrip", 0, 1); /* TODO: nargs */