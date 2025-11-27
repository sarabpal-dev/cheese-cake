#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define TARGET_SYMBOL "__arm64_sys_capset"
#define PHYS_ADDR 0x140ca4
#define MAX_SIZE 0x48c
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
    printf("Physical: 0x%x\n", PHYS_ADDR);
    printf("Max Size: 0x%x (%u bytes)\n\n", MAX_SIZE, MAX_SIZE);
    
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
    
    // Disassemble with radare2
    printf("=== Disassembly ===\n");
    snprintf(cmd, sizeof(cmd),
             "r2 -a arm -b 64 -q -c 'pd %zu @ 0' %s 2>&1",
             actual_size / 4, TMP_BIN);
    system(cmd);
    
    // Try objdump if available
    printf("\n=== Alternative (objdump) ===\n");
    snprintf(cmd, sizeof(cmd),
             "aarch64-linux-gnu-objdump -D -b binary -m aarch64 %s 2>&1",
             TMP_BIN);
    system(cmd);
    
    // Show function statistics
    printf("\n=== Function Statistics ===\n");
    printf("Physical offset: 0x%x\n", PHYS_ADDR);
    printf("Function size:   %zu bytes (%zu instructions)\n", actual_size, actual_size / 4);
    printf("Saved to:        %s\n", TMP_BIN);
    
    return 0;
}
