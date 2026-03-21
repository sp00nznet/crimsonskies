#!/usr/bin/env python3
"""
Post-generation fix for cross-function gotos and CMP_EQ issues.

Applied after run_pipeline.py to fix:
1. Cross-function gotos → RECOMP_ITAIL tail calls
2. Single-arg CMP_EQ from FPU comparisons → _fpu_cmp == 0
3. Duplicate RECOMP_GENERATED_CODE macro definition
"""

import re
import os
import glob

gen_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src', 'recomp', 'gen')

def get_all_labels_in_function(lines, func_start_line, func_end_line):
    """Get all labels defined within a function."""
    labels = set()
    for i in range(func_start_line, func_end_line):
        m = re.match(r'^(L_[0-9A-Fa-f]+):', lines[i])
        if m:
            labels.add(m.group(1))
    return labels

def fix_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    # Find function boundaries
    func_ranges = []
    func_start = None
    for i, line in enumerate(lines):
        if re.match(r'^void sub_[0-9A-Fa-f]+\(void\)', line):
            if func_start is not None:
                func_ranges.append((func_start, i))
            func_start = i
    if func_start is not None:
        func_ranges.append((func_start, len(lines)))

    fixes = 0

    for start, end in func_ranges:
        labels_in_func = get_all_labels_in_function(lines, start, end)

        for i in range(start, end):
            line = lines[i]

            # Fix cross-function gotos
            m = re.match(r'(\s+)goto (L_([0-9A-Fa-f]+));(.*)', line)
            if m:
                indent, label, addr, comment = m.groups()
                if label not in labels_in_func:
                    lines[i] = f'{indent}RECOMP_ITAIL(0x{addr}u); return;{comment}\n'
                    fixes += 1

            # Fix single-arg CMP_EQ (FPU comparison result)
            m = re.search(r'CMP_EQ\((_fpu_cmp)\)', line)
            if m:
                lines[i] = line.replace(f'CMP_EQ({m.group(1)})', f'({m.group(1)} == 0)')
                fixes += 1

            # Same for CMP_NE, etc.
            for macro in ['CMP_NE', 'CMP_EQ', 'CMP_L', 'CMP_LE', 'CMP_G', 'CMP_GE']:
                pattern = f'{macro}(_fpu_cmp)'
                if pattern in line:
                    if macro == 'CMP_EQ':
                        repl = '(_fpu_cmp == 0)'
                    elif macro == 'CMP_NE':
                        repl = '(_fpu_cmp != 0)'
                    elif macro == 'CMP_L':
                        repl = '(_fpu_cmp < 0)'
                    elif macro == 'CMP_LE':
                        repl = '(_fpu_cmp <= 0)'
                    elif macro == 'CMP_G':
                        repl = '(_fpu_cmp > 0)'
                    elif macro == 'CMP_GE':
                        repl = '(_fpu_cmp >= 0)'
                    lines[i] = lines[i].replace(pattern, repl)
                    fixes += 1

    # Fix duplicate RECOMP_GENERATED_CODE
    for i, line in enumerate(lines):
        if line.strip() == '#define RECOMP_GENERATED_CODE':
            lines[i] = '/* #define RECOMP_GENERATED_CODE -- set via CMake */\n'
            fixes += 1

    if fixes > 0:
        with open(filepath, 'w') as f:
            f.writelines(lines)

    return fixes

total_fixes = 0
for filepath in sorted(glob.glob(os.path.join(gen_dir, 'recomp_*.c'))):
    n = fix_file(filepath)
    if n > 0:
        print(f'  {os.path.basename(filepath)}: {n} fixes')
        total_fixes += n

print(f'\nTotal: {total_fixes} fixes applied')
