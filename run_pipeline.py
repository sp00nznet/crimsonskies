#!/usr/bin/env python3
"""
Crimson Skies Static Recompilation Pipeline

Runs the pcrecomp toolchain on the decrypted CRIMSON.ICD binary.
Adapts the paths/imports for the crimsonskies project layout.

Usage:
    python run_pipeline.py [decrypted_exe] [output_dir]
"""

import sys
import os

# Set up import paths for pcrecomp modules
pcrecomp_root = os.path.join(os.path.dirname(__file__), 'tools', 'pcrecomp', 'tools')
sys.path.insert(0, os.path.join(pcrecomp_root, 'pe'))
sys.path.insert(0, os.path.join(pcrecomp_root, 'lift'))

# Import the modules we need directly
from pe_analyze import analyze_pe, build_iat_map
from lift32 import Lifter

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM
import json
import time
import struct


# ---- Inlined from generate.py (can't import due to path issues) ----

COND_JUMPS = {
    'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe',
    'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno',
    'jp', 'jnp', 'jcxz', 'jecxz',
}


class LinearInstruction:
    __slots__ = ['address', 'size', 'mnemonic', 'op_str', 'bytes', 'operands',
                 'is_call', 'is_ret', 'is_cond_jump', 'is_uncond_jump', 'is_jump']

    def __init__(self, insn):
        self.address = insn.address
        self.size = insn.size
        self.mnemonic = insn.mnemonic
        self.op_str = insn.op_str
        self.bytes = bytes(insn.bytes)
        self.operands = list(insn.operands) if insn.operands else []
        self.is_call = insn.mnemonic == 'call'
        self.is_ret = insn.mnemonic in ('ret', 'retn', 'retf')
        self.is_cond_jump = insn.mnemonic in COND_JUMPS
        self.is_uncond_jump = insn.mnemonic == 'jmp'
        self.is_jump = self.is_cond_jump or self.is_uncond_jump

    @property
    def end_address(self):
        return self.address + self.size

    def get_branch_target(self):
        if self.operands:
            op = self.operands[0]
            if op.type == X86_OP_IMM:
                return op.imm & 0xFFFFFFFF
        return None

    def __repr__(self):
        return f"0x{self.address:08X}: {self.mnemonic} {self.op_str}"


def find_entries(code_data, code_start, code_end):
    call_targets = set()
    for i in range(len(code_data) - 5):
        if code_data[i] == 0xE8:
            rel = struct.unpack_from('<i', code_data, i + 1)[0]
            target = (code_start + i + 5 + rel) & 0xFFFFFFFF
            if code_start <= target < code_end:
                call_targets.add(target)
    prologues = set()
    for i in range(len(code_data) - 3):
        if code_data[i:i+3] == b'\x55\x8B\xEC':
            prologues.add(code_start + i)
        if i > 0 and code_data[i-1] in (0xCC, 0x90, 0xC3):
            if code_data[i] == 0x83 and code_data[i+1] == 0xEC:
                prologues.add(code_start + i)
    return sorted(call_targets | prologues)


def linear_disassemble_function(md, code_data, code_start, func_start, func_end):
    offset = func_start - code_start
    size = func_end - func_start
    if offset < 0 or offset + size > len(code_data):
        return [], set()
    raw = code_data[offset:offset + size]
    instructions = []
    leaders = {func_start}
    for insn in md.disasm(raw, func_start):
        li = LinearInstruction(insn)
        instructions.append(li)
        if li.is_cond_jump:
            target = li.get_branch_target()
            if target and func_start <= target < func_end:
                leaders.add(target)
            leaders.add(li.end_address)
        elif li.is_uncond_jump:
            target = li.get_branch_target()
            if target and func_start <= target < func_end:
                leaders.add(target)
            leaders.add(li.end_address)
        if li.mnemonic == 'int3':
            break
    return instructions, leaders


def lift_function_linear(lifter, name, instructions, leaders, func_start):
    lines = []
    lines.append(f'void {name}(void) {{')
    lines.append(f'    uint32_t ebp = 0;')
    lines.append(f'    double _st[8] = {{0}};')
    lines.append(f'    int _fp_top = 0;')
    lines.append(f'    int _fpu_cmp = 0;')
    lines.append(f'    uint32_t _cf = 0;')
    lines.append(f'    int _df = 1;')
    lines.append(f'    uint16_t _fpu_cw = 0x037F;')
    lines.append(f'')
    lifter._flag_state = None
    for insn in instructions:
        if insn.address in leaders:
            lines.append(f'L_{insn.address:08X}:')
        lifted = lifter.lift_instruction(insn)
        for line in lifted:
            lines.append(f'    {line}')
    if instructions and not instructions[-1].is_ret:
        lines.append('    return; /* end of function */')
    lines.append('}')
    return '\n'.join(lines)


def write_chunk(output_dir, file_idx, funcs):
    filename = f'recomp_{file_idx:04d}.c'
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        f.write('/* Crimson Skies Recompilation - Auto-generated - DO NOT EDIT */\n')
        f.write(f'/* File {file_idx}: {len(funcs)} functions */\n\n')
        f.write('#define RECOMP_GENERATED_CODE\n')
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n')
        f.write('#include <math.h>\n')
        f.write('#include <string.h>\n\n')
        for code, addr, name in funcs:
            f.write(code)
            f.write('\n\n')


# ---- End inlined code ----


def main():
    exe_path = sys.argv[1] if len(sys.argv) > 1 else 'analysis/CRIMSON_decrypted.exe'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'src/recomp/gen'
    split_size = int(sys.argv[3]) if len(sys.argv) > 3 else 500

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs('config', exist_ok=True)

    print(f'=== Crimson Skies Static Recompilation Pipeline ===', flush=True)
    print(f'[*] Binary: {exe_path}', flush=True)
    print(f'[*] Output: {output_dir}', flush=True)
    print(flush=True)

    # Step 1: PE Analysis
    print(f'[*] Step 1: PE Analysis...', flush=True)
    info = analyze_pe(exe_path)
    iat_map = build_iat_map(info)
    print(f'[*]   Image base: 0x{info.image_base:08X}', flush=True)
    print(f'[*]   Code: 0x{info.code_start:08X} - 0x{info.code_end:08X}', flush=True)
    print(f'[*]   IAT entries: {len(iat_map)}', flush=True)

    with open(exe_path, 'rb') as f:
        pe_data = f.read()

    text_sect = [s for s in info.sections if s.name == '.text'][0]
    offset = text_sect.raw_offset
    size = min(text_sect.virtual_size, text_sect.raw_size)
    code_data = pe_data[offset:offset + size]
    code_start = info.code_start
    code_end = info.code_end
    print(f'[*]   Code size: {len(code_data):,} bytes', flush=True)

    # Step 2: Function Discovery
    print(f'\n[*] Step 2: Function Discovery...', flush=True)
    entries = find_entries(code_data, code_start, code_end)
    print(f'[*]   Found {len(entries)} function entries', flush=True)

    # Step 3: Disassembly + Lifting
    print(f'\n[*] Step 3: Disassembly + Code Generation...', flush=True)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lifter = Lifter(iat_map=iat_map)

    all_entries = []
    func_stats = []
    error_count = 0
    file_idx = 0
    chunk_funcs = []
    start = time.time()

    for idx, addr in enumerate(entries):
        if idx + 1 < len(entries):
            func_end = min(entries[idx + 1], addr + 65536)
        else:
            func_end = min(code_end, addr + 65536)

        if func_end - addr < 2:
            continue

        name = f'sub_{addr:08X}'

        try:
            instructions, leaders = linear_disassemble_function(
                md, code_data, code_start, addr, func_end)

            if not instructions:
                continue

            trimmed = []
            seen_ret = False
            for insn in instructions:
                if insn.mnemonic == 'int3':
                    break
                if seen_ret:
                    if insn.address not in leaders:
                        continue
                    seen_ret = False
                trimmed.append(insn)
                if insn.is_ret:
                    seen_ret = True
            if not trimmed:
                continue

            code = lift_function_linear(lifter, name, trimmed, leaders, addr)
            chunk_funcs.append((code, addr, name))
            all_entries.append((addr, name))

            func_stats.append({
                'address': f'0x{addr:08X}',
                'address_int': addr,
                'name': name,
                'num_instructions': len(trimmed),
            })

        except Exception as e:
            stub = f'/* ERROR: {name} at 0x{addr:08X}: {e} */\nvoid {name}(void) {{ /* error */ }}\n'
            chunk_funcs.append((stub, addr, name))
            all_entries.append((addr, name))
            error_count += 1

        if len(chunk_funcs) >= split_size:
            write_chunk(output_dir, file_idx, chunk_funcs)
            elapsed = time.time() - start
            rate = len(all_entries) / elapsed if elapsed > 0 else 0
            print(f'[*]   {len(all_entries)}/{len(entries)} functions '
                  f'({file_idx + 1} files, {rate:.0f}/s, {error_count} err)', flush=True)
            file_idx += 1
            chunk_funcs = []

    if chunk_funcs:
        write_chunk(output_dir, file_idx, chunk_funcs)
        file_idx += 1

    # Step 4: Header + Dispatch Table
    print(f'\n[*] Step 4: Header + Dispatch Table...', flush=True)

    header_path = os.path.join(output_dir, 'recomp_funcs.h')
    with open(header_path, 'w') as f:
        f.write('/* Crimson Skies Recompilation - Auto-generated - DO NOT EDIT */\n')
        f.write('#pragma once\n#include <stdint.h>\n\n')
        f.write(f'/* {len(all_entries)} recompiled functions */\n\n')
        for addr, name in all_entries:
            f.write(f'void {name}(void);  /* 0x{addr:08X} */\n')

    dispatch_path = os.path.join(output_dir, 'recomp_dispatch.c')
    with open(dispatch_path, 'w') as f:
        f.write('/* Crimson Skies Recompilation - Auto-generated - DO NOT EDIT */\n\n')
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n\n')
        f.write('const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n')
        for addr, name in sorted(all_entries, key=lambda x: x[0]):
            f.write(f'    {{ 0x{addr:08X}u, {name} }},\n')
        f.write('};\n\n')
        f.write(f'const uint32_t recomp_dispatch_count = {len(all_entries)};\n')

    with open('config/functions.json', 'w') as f:
        json.dump(func_stats, f, indent=2)

    # Summary
    elapsed = time.time() - start
    total_lines = 0
    total_bytes = 0
    for fn in os.listdir(output_dir):
        fp = os.path.join(output_dir, fn)
        if os.path.isfile(fp):
            total_bytes += os.path.getsize(fp)
            with open(fp, 'r') as rf:
                total_lines += sum(1 for _ in rf)

    print(f'\n{"="*60}', flush=True)
    print(f'  CRIMSON SKIES RECOMPILATION COMPLETE', flush=True)
    print(f'{"="*60}', flush=True)
    print(f'  Functions:      {len(all_entries):,}', flush=True)
    print(f'  Source files:   {file_idx}', flush=True)
    print(f'  Errors:         {error_count}', flush=True)
    print(f'  Lines of C:     {total_lines:,}', flush=True)
    print(f'  Generated size: {total_bytes / 1048576:.1f} MB', flush=True)
    print(f'  Time:           {elapsed:.1f}s', flush=True)
    print(f'{"="*60}', flush=True)


if __name__ == '__main__':
    main()
