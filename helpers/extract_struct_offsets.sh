#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <vmlinux>"
    exit 1
fi

VMLINUX="$1"

if [ ! -f "$VMLINUX" ]; then
    echo "Error: File $VMLINUX not found"
    exit 1
fi

# Check if pahole is installed
if ! command -v pahole &> /dev/null; then
    echo "Error: pahole is not installed. Install with: sudo apt install dwarves"
    exit 1
fi

echo "=== Update exploit.c with these values ==="
echo ""

# Extract task_struct offsets (handle variable whitespace)
tasks_offset=$(pahole -C task_struct "$VMLINUX" | grep "struct list_head.*tasks;" | grep -oP '/\*\s*\K\d+' | head -1)
mm_offset=$(pahole -C task_struct "$VMLINUX" | grep "struct mm_struct \*.*mm;" | grep -oP '/\*\s*\K\d+' | head -1)
pid_offset=$(pahole -C task_struct "$VMLINUX" | grep "pid_t.*pid;" | grep -oP '/\*\s*\K\d+' | head -1)
seccomp_offset=$(pahole -C task_struct "$VMLINUX" | grep "struct seccomp.*seccomp;" | grep -oP '/\*\s*\K\d+' | head -1)

# Extract mm_struct offsets
pgd_offset=$(pahole -C mm_struct "$VMLINUX" | grep "pgd_t \*.*pgd;" | grep -oP '/\*\s*\K\d+' | head -1)

# Print exploit.c changes
if [ -n "$mm_offset" ]; then
    printf "Line 123: #define OFFSETOF_TASK_STRUCT_MM 0x%x\n" "$mm_offset"
else
    echo "Warning: Could not find task_struct->mm offset"
fi

if [ -n "$pgd_offset" ]; then
    printf "Line 124: #define OFFSETOF_MM_PGD 0x%x\n" "$pgd_offset"
else
    echo "Warning: Could not find mm_struct->pgd offset"
fi

echo ""
echo "Note: task_struct->tasks, ->pid, ->seccomp offsets are used in task iteration code"
echo "These are typically hardcoded in the exploit and may need manual verification"

if [ -n "$tasks_offset" ]; then
    printf "task_struct->tasks = 0x%x\n" "$tasks_offset"
else
    echo "Warning: Could not find task_struct->tasks offset"
fi

if [ -n "$pid_offset" ]; then
    printf "task_struct->pid = 0x%x\n" "$pid_offset"
else
    echo "Warning: Could not find task_struct->pid offset"
fi

if [ -n "$seccomp_offset" ]; then
    printf "task_struct->seccomp = 0x%x\n" "$seccomp_offset"
else
    echo "Warning: Could not find task_struct->seccomp offset"
fi
