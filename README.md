# DEMONSTRATION
[2025-11-15 23-29-48 (2).webm](https://github.com/user-attachments/assets/8332aaeb-2e76-4e52-b46e-b035b10bf4ca)

## 🧪 dirtypageflags Branch
The `dirtypageflags` branch demonstrates a technique to modify page flags and use them to achieve **write access to otherwise read-only system binaries**.

In the demo video, this method successfully:
- Overwrites a binary inside **/system/bin/**
- Shows that arbitrary file modification is possible
- Illustrates how this can be abused to gain **root privileges** by overwriting critical executables

⚠️ **Important Limitation**  
The modifications are **not persistent**.  
After a reboot, Android restores the original system image, causing all changes made through this method to be reverted automatically even files inside /data/.

Despite being non-persistent, this technique still represents a powerful primitive for:
- Temporary privilege escalation  
- Local code execution  
- On-the-fly binary patching 

**PRs are welcomed to extend this technique and develop a stable path to full root.**

## 📚 References
https://ptr-yudai.hatenablog.com/entry/2025/09/14/180326
