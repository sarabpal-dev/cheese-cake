#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define TARGET_SYMBOL "__do_sys_capset"
#define VIRT_ADDR 0xffffffe4ee740ca4    //cat kallsyms.txt | grep -A2 "__do_sys_capset"
#define VIRT_NEXT 0xffffffe4ee741130
#define PHYS_ADDR 0x140ca4   // __do_sys_capset - _text
#define MAX_SIZE (VIRT_NEXT - VIRT_ADDR)
#define TMP_BIN "func.bin"

// Find actual function end by looking for ret instruction
size_t find_function_end(unsigned char *buffer, size_t max_size) {
    for (size_t i = 0; i < max_size; i += 4) {
        uint32_t insn = *(uint32_t *)(buffer + i);
        // Check for ret instruction (0xd65f03c0)
        if (insn == 0xd65f03c0) {
            return i + 4; // Include the ret instruction
        }
    }
    return max_size;
}

int main(int argc, char *argv[]) {
    int fd;
    unsigned char buffer[MAX_SIZE];
    FILE *tmp;
    char cmd[1024];
    char *kernel_file;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <kernel_binary>\n", argv[0]);
        return 1;
    }
    kernel_file = argv[1];
    
    printf("Kernel Function Analyzer\n");
    printf("========================\n");
    printf("Function: %s\n", TARGET_SYMBOL);
    printf("Virtual:  0x%lx\n", VIRT_ADDR);
    printf("Physical: 0x%lx\n", PHYS_ADDR);
    printf("Max Size: 0x%lx (%lu bytes)\n\n", MAX_SIZE, MAX_SIZE);
    
    // Read maximum possible function size
    fd = open(kernel_file, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    if (lseek(fd, PHYS_ADDR, SEEK_SET) == (off_t)-1) {
        perror("lseek");
        close(fd);
        return 1;
    }
    
    ssize_t bytes_read = read(fd, buffer, MAX_SIZE);
    close(fd);
    
    if (bytes_read < 0) {
        perror("read");
        return 1;
    }
    
    // Find actual function end
    size_t actual_size = find_function_end(buffer, bytes_read);
    
    printf("Read %zd bytes\n", bytes_read);
    printf("Actual function size: 0x%zx (%zu bytes, %zu instructions)\n\n",
           actual_size, actual_size, actual_size / 4);
    
    // Save actual function to temp file
    tmp = fopen(TMP_BIN, "wb");
    if (!tmp) {
        perror("fopen");
        return 1;
    }
    fwrite(buffer, 1, actual_size, tmp);
    fclose(tmp);
    
    // Disassemble with objdump
    printf("=== objdump disassembly ===\n");
    snprintf(cmd, sizeof(cmd),
             "objdump -D -b binary -m aarch64 --adjust-vma=0x%lx %s 2>/dev/null",
             VIRT_ADDR, TMP_BIN);
    system(cmd);
    
    // Disassemble with radare2
    printf("\n=== radare2 analysis ===\n");
    snprintf(cmd, sizeof(cmd),
             "r2 -a arm -b 64 -q -c 'pd %zu @ 0' %s 2>/dev/null",
             actual_size / 4, TMP_BIN);
    system(cmd);
    
    // Show function statistics
    printf("\n=== Function Statistics ===\n");
    printf("Start address:  0x%lx\n", VIRT_ADDR);
    printf("End address:    0x%lx\n", VIRT_ADDR + actual_size);
    printf("Function size:  %zu bytes (%zu instructions)\n", actual_size, actual_size / 4);
    printf("Next function:  0x%lx (ptrace_access_vm)\n", VIRT_NEXT);
    printf("Gap/padding:    0x%lx bytes\n", VIRT_NEXT - VIRT_ADDR - actual_size);
    
    // Cleanup
    unlink(TMP_BIN);
    
    return 0;
}
