# 🛡️✨  Aegis ✨🛡️
#  Aegis - Multi-Layer Active Defense System


Project Aegis is a multi-layer proactive security system operating in both User Mode and Kernel Mode. It automatically detects, analyzes, reports, and removes malware including viruses, worms, trojans, spyware, keyloggers, rootkits, and ransomware.

---

## Key Features

- **Multi-layer Protection**: Behavior monitoring, signature analysis, heuristics, memory & kernel-level monitoring  
- **Rootkit Detection**: Detects user-mode & kernel-mode rootkits using SSDT/IDT and DKOM techniques  
- **Ransomware Protection**: Detects encryption activity, locates memory keys, and auto-decrypts files when possible  
- **User-Friendly GUI**: Clear threat info with user decision control  
- **Self-Protection**: Prevents tampering by malware  
- **Optimized Performance**: Minimal impact on system resources

---

## System Requirements

- Windows 10 (1607+) or Windows Server 2016+  
- ≥ 2GB RAM  
- ≥ 1GHz CPU  
- ≥ 500MB free disk  
- Administrator privileges for install & run

---

## Installation & Setup

### 1. Build

**Kernel Driver (`AegisKernel.sys`)**: Visual Studio + WDK → KMDF project → copy source → Release build (x86/x64)  
**User Application (`AegisGUI.cpp`)**: Visual Studio → Windows Desktop App project → copy source → Release build

### 2. Install Driver

Run Command Prompt as Admin:
```
sc create AegisKernel type= kernel binPath= "C:\path\to\AegisKernel.sys"
sc start AegisKernel
```

### 3. Configure GUI

Run `AegisGUI.exe` as Admin → **Management** tab → update allow/block lists & protection options.

---

## Usage

**Main Tabs**: Dashboard | History | Management | Reports  

**Scanning**: Quick Scan (important areas) | Full Scan (entire system including memory & registry)  

**Threat Handling**:  


### 3. Configure GUI

Run `AegisGUI.exe` as Admin → **Management** tab → update allow/block lists & protection options.

---

## Usage

**Main Tabs**: Dashboard | History | Management | Reports  

**Scanning**: Quick Scan (important areas) | Full Scan (entire system including memory & registry)  

**Threat Handling**:  
```text
+---------------------------------------------------------------------------------+
|                       [WARNING ICON] - AEGIS DETECTOR                            |
|                                                                                 |
| Critical threat detected!                                                        |
|                                                                                 |
| Name: [Threat Name]                                                             |
| Location: [File/Process Path]                                                   |
| Level: [Threat Level]                                                           |
|                                                                                 |
| Description: [Detailed Threat Info]                                            |
|                                                                                 |
| Recommendation: [Suggested Action]                                             |
|                                                                                 |
| [ Quarantine & Delete ] [ Quarantine ] [ Allow ] [ Details ]                     |
+---------------------------------------------------------------------------------+
```

- **Delete**: Permanently remove  
- **Quarantine**: Isolate for analysis  
- **Allow**: Add to whitelist  
- **Details**: Full threat info

**Management**: Add/remove items in Allow/Block lists, view & restore quarantined files  
**Ransomware Decryption**: Auto-stop ransomware, find memory key, decrypt files, generate report

---

## Advanced Configuration

- **Update Signatures**: Management → Update Signatures  
- **Protection Options**: File → Settings → Real-time, Auto-quarantine, Behavior Analysis, Ransomware, Memory, Network  
- **Scheduled Scans**: Dashboard → Schedule Scan

---

## Troubleshooting

- **Driver fails**: Check Admin rights, Windows compatibility, Event Viewer  
- **Threats not detected**: Enable real-time protection, update signatures, check allow/block lists  
- **Ransomware decryption fails**: Ensure ransomware stopped, key found, some strong-encryption ransomware cannot be decrypted

---

## Tips for Effective Use

- Update signatures weekly  
- Perform full system scans regularly  
- Review alerts carefully  
- Backup important data  
- Use with firewall & OS updates

---

## FAQs

- **Does it affect performance?** Minimal impact; scans run at low priority  
- **How to verify if a file is safe?** Check details, research online, or use online scanners  
- **Does it protect against 0-day threats?** Yes, via behavior analysis & kernel monitoring  
- **Can I disable notifications?** Yes, in Settings (not recommended)

---

## License

GNU GPL v3.0 – see LICENSE file

---

## Contact

- Email: nammoleong@gmail.com
- GitHub: [https://github.com/Yuri08loveElaina/Aegis](https://github.com/Yuri08loveElaina/Aegis)  

**Note:** Use responsibly on authorized systems only. No liability for misuse.

