# DEMONSTRATION
[2025-11-16 16-10-05.webm](https://github.com/user-attachments/assets/6356690b-59b1-4454-87ac-34754afe30c9)

## 🔬 proc-rw Branch
The `proc-rw` branch demonstrates a practical example of obtaining r/w access to any process.

As a demonstration, this branch shows how to:
- Read memory from the **init** process  
- Dump `libbase.so` directly from the running process  

This is only a **proof-of-concept**.  
With further development, the same technique can be extended to:
- Inject custom shellcode into a **root-owned** process  
- Escalate privileges to full **root access**  
- Patch security checks or hijack execution flow in privileged services

🤝 Contribution
- **PRs are welcomed to improve the exploit chain and help reach stable, full root privilege escalation.**
