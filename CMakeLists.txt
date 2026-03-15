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

# Collect all generated source files
file(GLOB RECOMP_GENERATED_SOURCES "src/recomp/gen/recomp_*.c")

# Recompiled game executable
add_executable(crimson WIN32
    src/game/main.c
    src/game/imports.c
    src/game/com_mocks.c
    ${RECOMP_GENERATED_SOURCES}
)

target_include_directories(crimson PRIVATE
    src/game
    src/recomp
    src/recomp/gen
)

# Generated code uses the RECOMP_GENERATED_CODE define for register aliases
set_source_files_properties(${RECOMP_GENERATED_SOURCES} PROPERTIES
    COMPILE_DEFINITIONS "RECOMP_GENERATED_CODE"
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
    /wd4146       # Suppress unary minus on unsigned
    /wd4305       # Suppress double->float truncation
    /wd4267       # Suppress size_t->uint32 conversion
    /wd4090       # Suppress const qualifier difference
    /wd4102       # Suppress unreferenced label
    /bigobj       # Large object files (generated code is big)
)

target_compile_definitions(crimson PRIVATE
    WIN32
    _WINDOWS
    _CRT_SECURE_NO_DEPRECATE
    NOMINMAX
    CRIMSON_SKIES_RECOMP
)
