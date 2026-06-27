#!/usr/bin/env python3
"""
Generate va_holder.dll — a minimal PE DLL that reserves VA space for the
Crimson Skies recompilation.

The DLL has image base 0x00010000 and a single large RWX section covering
VA 0x11000 through 0xA2A000. When statically linked, the PE loader maps
it BEFORE NLS locale files and the process heap, preventing them from
occupying our target address ranges.

The DLL exports one dummy function ("va_holder_init") so the main EXE
can link against it.

VA layout (with DLL ImageBase = 0x00010000):
  PE header:  VA 0x00010000 (1 page, not usable)
  .rsrv:      VA 0x00011000 - 0x00A2A000 (covers SEH, stack, and data ranges)
    - 0x10000-0x20000  SEH guard area
    - 0x100000-0x200000  recomp stack
    - 0x603000-0xA2A000  .rdata/.data/.idata/.rsrc
"""

import struct
import sys
import os

def align(v, a):
    return (v + a - 1) & ~(a - 1)

def build_dll(output_path):
    IMAGE_BASE = 0x00010000
    SECTION_ALIGN = 0x1000
    FILE_ALIGN = 0x200

    # Section: covers VA 0x11000 to 0xA2A000
    # RVA = VA - ImageBase = 0x11000 - 0x10000 = 0x1000
    section_rva = 0x1000
    section_va_end = 0x00A2A000
    section_vsize = section_va_end - (IMAGE_BASE + section_rva)  # 0xA19000
    section_raw_size = FILE_ALIGN  # minimal raw data (demand-zero for rest)

    # Export directory — one dummy export
    export_func_name = b"va_holder_init"
    dll_name = b"va_holder.dll"

    # Build the PE
    # DOS header
    dos_header = bytearray(64)
    struct.pack_into('<H', dos_header, 0, 0x5A4D)  # e_magic = "MZ"
    pe_offset = 64
    struct.pack_into('<I', dos_header, 0x3C, pe_offset)  # e_lfanew

    # PE signature
    pe_sig = struct.pack('<I', 0x00004550)  # "PE\0\0"

    # COFF header
    num_sections = 1
    coff_header = struct.pack('<HHIIIHH',
        0x014C,         # Machine: i386
        num_sections,   # NumberOfSections
        0,              # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        0xE0,           # SizeOfOptionalHeader (PE32)
        0x2102          # Characteristics: DLL | EXECUTABLE | 32BIT
    )

    # Calculate layout
    headers_size = pe_offset + 4 + 20 + 0xE0 + num_sections * 40
    headers_raw = align(headers_size, FILE_ALIGN)

    # Export data comes right after section raw data
    # Put export directory in the section's raw data
    export_dir_rva = section_rva  # export data at start of section

    # Build export directory
    # Layout within export area:
    # [0x00] Export Directory Table (40 bytes)
    # [0x28] Address Table (4 bytes, 1 function)
    # [0x2C] Name Pointer Table (4 bytes, 1 name)
    # [0x30] Ordinal Table (2 bytes, 1 ordinal)
    # [0x34] DLL name string
    # [0x34+len] Function name string
    # [0x34+len+len2] Function code (ret instruction)

    dll_name_rva = export_dir_rva + 0x34
    func_name_rva = dll_name_rva + len(dll_name) + 1
    func_code_rva = align(func_name_rva + len(export_func_name) + 1, 4)
    addr_table_rva = export_dir_rva + 0x28
    name_ptr_table_rva = export_dir_rva + 0x2C
    ordinal_table_rva = export_dir_rva + 0x30

    export_dir = struct.pack('<IIIHHHIIIII',
        0,                  # Characteristics
        0,                  # TimeDateStamp
        0, 0,               # MajorVersion, MinorVersion
        dll_name_rva,       # Name RVA
        1,                  # OrdinalBase
        1,                  # NumberOfFunctions
        1,                  # NumberOfNames
        addr_table_rva,     # AddressOfFunctions
        name_ptr_table_rva, # AddressOfNames
        ordinal_table_rva   # AddressOfNameOrdinals
    )

    # Address table: RVA of the function
    addr_table = struct.pack('<I', func_code_rva)

    # Name pointer table
    name_ptr_table = struct.pack('<I', func_name_rva)

    # Ordinal table
    ordinal_table = struct.pack('<H', 0)

    # Pad to alignment
    pad1 = b'\x00' * (0x34 - len(export_dir) - len(addr_table) - len(name_ptr_table) - len(ordinal_table))

    # Strings
    dll_name_bytes = dll_name + b'\x00'
    func_name_bytes = export_func_name + b'\x00'

    # Function code: DllMain and va_holder_init both just return 1
    # Align to 4 bytes
    code_offset = func_code_rva - export_dir_rva
    pre_code_pad = b'\x00' * (code_offset - (0x34 + len(dll_name_bytes) + len(func_name_bytes)))

    # mov eax, 1; ret 0xC (DllMain is stdcall with 3 args)
    dllmain_code = b'\xB8\x01\x00\x00\x00\xC2\x0C\x00'
    # For va_holder_init: ret (cdecl, no args)
    init_code = b'\xB8\x01\x00\x00\x00\xC3'

    # DllMain RVA (right after init_code)
    dllmain_rva = func_code_rva + len(init_code)

    # Build raw section data
    export_data = (export_dir + addr_table + name_ptr_table + ordinal_table +
                   pad1 + dll_name_bytes + func_name_bytes + pre_code_pad +
                   init_code + dllmain_code)

    section_raw = export_data
    section_raw_padded = section_raw + b'\x00' * (align(len(section_raw), FILE_ALIGN) - len(section_raw))
    actual_raw_size = len(section_raw_padded)

    # SizeOfImage: must cover all sections
    size_of_image = align(section_rva + section_vsize, SECTION_ALIGN)

    # Entry point = DllMain
    entry_point_rva = dllmain_rva

    # Optional header (PE32)
    # Data directories: 16 entries, only export (index 0) is populated
    data_dirs = bytearray(16 * 8)
    struct.pack_into('<II', data_dirs, 0, export_dir_rva, 40)  # Export directory

    # PE32 Optional Header — build field by field
    optional_header = b''
    optional_header += struct.pack('<H', 0x010B)    # Magic: PE32
    optional_header += struct.pack('<BB', 14, 0)    # Linker version
    optional_header += struct.pack('<I', len(init_code) + len(dllmain_code))  # SizeOfCode
    optional_header += struct.pack('<I', 0)         # SizeOfInitializedData
    optional_header += struct.pack('<I', section_vsize)  # SizeOfUninitializedData
    optional_header += struct.pack('<I', entry_point_rva)  # AddressOfEntryPoint
    optional_header += struct.pack('<I', section_rva)   # BaseOfCode
    optional_header += struct.pack('<I', section_rva)   # BaseOfData
    optional_header += struct.pack('<I', IMAGE_BASE)    # ImageBase
    optional_header += struct.pack('<I', SECTION_ALIGN) # SectionAlignment
    optional_header += struct.pack('<I', FILE_ALIGN)    # FileAlignment
    optional_header += struct.pack('<HH', 6, 0)         # OS Version
    optional_header += struct.pack('<HH', 0, 0)         # Image Version
    optional_header += struct.pack('<HH', 6, 0)         # Subsystem Version
    optional_header += struct.pack('<I', 0)              # Win32VersionValue
    optional_header += struct.pack('<I', size_of_image)  # SizeOfImage
    optional_header += struct.pack('<I', headers_raw)    # SizeOfHeaders
    optional_header += struct.pack('<I', 0)              # CheckSum
    optional_header += struct.pack('<H', 2)              # Subsystem: GUI
    optional_header += struct.pack('<H', 0x0100)         # DllCharacteristics: NX_COMPAT, no ASLR
    optional_header += struct.pack('<I', 0x100000)       # SizeOfStackReserve
    optional_header += struct.pack('<I', 0x1000)         # SizeOfStackCommit
    optional_header += struct.pack('<I', 0x100000)       # SizeOfHeapReserve
    optional_header += struct.pack('<I', 0x1000)         # SizeOfHeapCommit
    optional_header += struct.pack('<I', 0)              # LoaderFlags
    optional_header += struct.pack('<I', 16)             # NumberOfRvaAndSizes
    optional_header += bytes(data_dirs)

    # Pad optional header to 0xE0
    optional_header += b'\x00' * (0xE0 - len(optional_header))

    # Section header
    section_header = struct.pack('<8sIIIIIIHHI',
        b'.rsrv\x00\x00\x00',  # Name
        section_vsize,          # VirtualSize
        section_rva,            # VirtualAddress
        actual_raw_size,        # SizeOfRawData
        headers_raw,            # PointerToRawData
        0,                      # PointerToRelocations
        0,                      # PointerToLineNumbers
        0,                      # NumberOfRelocations
        0,                      # NumberOfLineNumbers
        0xE00000E0              # Characteristics: CODE|INIT_DATA|UNINIT_DATA|READ|WRITE|EXECUTE
    )

    # Assemble PE
    pe = dos_header + pe_sig + coff_header + optional_header + section_header

    # Pad to headers_raw
    pe += b'\x00' * (headers_raw - len(pe))

    # Section raw data
    pe += section_raw_padded

    with open(output_path, 'wb') as f:
        f.write(pe)

    print(f"Generated {output_path}")
    print(f"  ImageBase:    0x{IMAGE_BASE:08X}")
    print(f"  Section .rsrv: RVA 0x{section_rva:08X}, VSize 0x{section_vsize:08X}")
    print(f"  VA coverage:  0x{IMAGE_BASE + section_rva:08X} - 0x{IMAGE_BASE + section_rva + section_vsize:08X}")
    print(f"  SizeOfImage:  0x{size_of_image:08X}")
    print(f"  File size:    {len(pe)} bytes")
    print(f"  Entry point:  0x{entry_point_rva:08X} (DllMain)")
    print(f"  Export:       {export_func_name.decode()} at RVA 0x{func_code_rva:08X}")

if __name__ == '__main__':
    output = sys.argv[1] if len(sys.argv) > 1 else 'va_holder.dll'
    build_dll(output)
