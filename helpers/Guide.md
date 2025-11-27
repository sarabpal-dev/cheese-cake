# Porting Guide for New Devices

This guide explains how to port the exploit to a different Android device. Follow these steps carefully.

## ⚠️ Important Notice

This exploit is **highly device-specific** and may not work out-of-the-box on every device. You may need to make additional code modifications beyond just updating offsets. The exploit's reliability varies across different devices and kernel configurations.

## Prerequisites

- Ability to extract boot.img from OTA update
- Basic knowledge of Android kernel structure
- Tools: `adb`, `pahole` (install with `sudo apt install dwarves`)

## Step 1: Extract boot.img

Get the boot.img from the same OTA update as your device's current firmware:

```bash
# Download OTA for your device
# Extract boot.img from the OTA package
unzip ota_package.zip boot.img
```

## Step 2: Extract Kernel from boot.img

```bash
# Use tools like unpackbootimg or extract-ikconfig
# This will give you the kernel binary
```

## Step 3: Extract kallsyms.txt

Use the helper tool to extract kernel symbols:

```bash
# Compile the helper
cd helpers
gcc extract-kallsyms.c -o extract-kallsyms

# Extract kallsyms from kernel
./extract-kallsyms /path/to/kernel > kallsyms.txt
```

**For v6 kernels or if extract-kallsyms.c doesn't work:**

```bash
# Clone vmlinux-to-elf
git clone https://github.com/marin-m/vmlinux-to-elf

# Extract kallsyms using kallsyms-finder
python3 vmlinux-to-elf/kallsyms-finder /path/to/kernel > kallsyms.txt
```

## Step 4: Extract Kernel Symbol Offsets

Run the offset extraction script:

```bash
./helpers/extract_offsets.sh kallsyms.txt
```

This will output something like:

```
=== Update exploit.c with these values ===

Line 677: swapper_pg_dir_off = idmap_pg_dir_off + 0x5000;
Line 680: uint64_t init_task_off = idmap_pg_dir_off + 0x321f80;
Line 1412: uint64_t selinux_state_offset = 0x5c4b88;

helpers/analyze.c:
#define PHYS_ADDR 0x140ca4   // __do_sys_capset - _text
#define MAX_SIZE 0x48c
```

**Update the specified lines in `exploit.c` and `helpers/analyze.c` with these values.**

**Note on __do_sys_capset (v5 vs v6 kernels):**
- **v5 kernels**: `__do_sys_capset` exists as a separate symbol - use this address
- **v6 kernels**: `__do_sys_capset` is inlined into `__arm64_sys_capset` - use `__arm64_sys_capset` address instead

### Kernel Physical Base Address

Most modern Android devices load the kernel starting at physical address **0xa8000000**. This is already configured in the exploit and you don't need to change it. If you want to verify, you can check the kernel source or device tree (DT) source.

## Step 5: Get vmlinux

You have two options:

### Option A: Use Pre-compiled vmlinux (Recommended)

1. Check the releases in [https://github.com/sarabpal-dev/GKI_KernelSU_SUSFS](https://github.com/sarabpal-dev/GKI_KernelSU_SUSFS) (link in releases)
2. Find vmlinux matching your kernel version (e.g., 5.10, 5.15, 6.5)
3. **Note:** Generally, offsets are the same for the same major.minor kernel version (e.g., all 5.10.x kernels)
4. Only the first two version numbers matter (5.10, not 5.10.123)
5. There's a small chance offsets differ even within the same version

### Option B: Compile from Source

If your device's kernel source is available, search online for how to compile Android kernel for your specific device.

## Step 6: Extract Structure Offsets

Run the structure offset extraction script:

```bash
./helpers/extract_struct_offsets.sh vmlinux
```

This will output:

```
=== Update exploit.c with these values ===

Line 122: #define OFFSETOF_TASK_STRUCT_MM 0x518
Line 123: #define OFFSETOF_MM_PGD 0x48

Hardcoded offsets in exploit.c:
Line 1055, 1065: task_struct->tasks = 0x4c8
Line 1069: task_struct->pid = 0x5c8
Line (seccomp shellcode): task_struct->seccomp = 0x848
```

**Update the specified lines in `exploit.c` with these values.**

### Manual Updates Required

The script identifies the lines, but you need to manually update:

- **Line 1055**: `uint64_t init_task_tasks_phys = cheese->init_task_phys + 0x4c8;`
- **Line 1065**: `uint64_t current_task_phys = current_tasks_member_phys - 0x4c8;`
- **Line 1069**: `uint64_t pid_addr = current_task_phys + 0x5c8;`
- **Seccomp shellcode**: Update the offset in shellcode that zeros seccomp structure (currently `0x848`)

## Step 7: Compile and Test

Refer to the main README for compilation and usage instructions.

## Troubleshooting

### Exploit Fails to Run

If the exploit fails:

1. **Reboot the device** and wait for ~2 minutes before trying again
2. Try running the exploit multiple times (it may succeed on subsequent attempts)
3. If it consistently fails after multiple reboots and attempts, you likely need to make additional code modifications beyond offset changes

### Samsung Devices

**Note:** This exploit will **not work on Samsung devices** due to Physical Address Space Layout Randomization (PhyASLR). However, it can be adapted to work with Samsung devices by implementing PhyASLR bypass techniques. See the writeup referenced in the main README for details on bypassing Samsung's PhyASLR.

### Kernel Panic After Write

If you successfully reach the kernel dump stage but experience a kernel panic after writing shellcode, you need to adapt the shellcode for your specific device. Use the provided `helpers/analyze.c` tool to print the `__do_sys_capset` function from your kernel dump. I have attached my `kernel.dump` in the repository which you can use as a reference to adapt the shellcode.
Good luck!


---

Use AI for more info :)
