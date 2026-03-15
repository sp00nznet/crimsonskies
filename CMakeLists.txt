cmake_minimum_required(VERSION 3.20)

project(CrimsonSkiesRecomp
    VERSION 0.1.0
    DESCRIPTION "Crimson Skies Static Recompilation"
    LANGUAGES C
)

# Must build as 32-bit x86
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "This project must be built as 32-bit (x86). Use -A Win32 with Visual Studio.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Recompiled game executable
add_executable(crimson WIN32
    src/game/main.c
    src/game/imports.c
    src/game/com_mocks.c
    # Generated source files will be added here as they're produced
    # src/recomp/gen/recomp_0000.c
    # src/recomp/gen/recomp_0001.c
    # ...
)

target_include_directories(crimson PRIVATE
    src/game
    src/recomp
)

# Link against Win32 libraries
target_link_libraries(crimson PRIVATE
    kernel32
    user32
    gdi32
    winmm
    advapi32
    shell32
    ole32
    comdlg32
)

# Linker settings matching original binary
target_link_options(crimson PRIVATE
    /DYNAMICBASE:NO       # No ASLR (fixed image base)
    /STACK:0x200000       # 2MB stack (matching original)
    /LARGEADDRESSAWARE:NO # 32-bit address space only
)

# Disable security features that interfere with recompiled code
target_compile_options(crimson PRIVATE
    /GS-          # No buffer security check
    /W3           # Warning level 3
    /wd4244       # Suppress narrowing conversion warnings
    /wd4018       # Suppress signed/unsigned comparison warnings
)

target_compile_definitions(crimson PRIVATE
    WIN32
    _WINDOWS
    _CRT_SECURE_NO_DEPRECATE
    NOMINMAX
    CRIMSON_SKIES_RECOMP
)
