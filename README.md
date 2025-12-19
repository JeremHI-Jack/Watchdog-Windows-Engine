# Windows Watchdog

<img width="400" height="400" alt="image" center src="https://github.com/user-attachments/assets/ed48393b-e841-4608-b46c-f11e57d9d79a" />


**Unified Endpoint Telemetry for Windows (Userland Agent)**

Windows Watchdog is a lightweight, transparent endpoint monitoring agent that aggregates native Windows telemetry into a single, real-time, human-readable timeline.

It is designed for **blue teamers, SOC analysts, DFIR practitioners, and security engineers** who require deep visibility into Windows activity **without kernel drivers, hooks, or invasive components**.

---

## features

### unified timeline
All collected events are normalized into a single chronological view, enabling immediate correlation between:
- system events  
- user actions  
- process activity  
- network connections  
- filesystem changes  

### native windows telemetry sources
Windows Watchdog relies **exclusively on built-in Windows capabilities**.

#### event logs
- System  
- Application  
- Security (when permissions allow)

#### modern event channels (operational)
- PowerShell / Operational  
- Windows Defender / Operational  
- WMI-Activity / Operational  
- TaskScheduler / Operational  
- WinRM / Operational  
- DNS Client / Operational  
- RDP / Terminal Services  
- Forwarded Events (if configured)  

Event channels are **auto-detected** and **safely disabled** if unavailable.

### process & command monitoring
- Full process creation tracking  
- Parent/child process relationships  
- Command-line capture  
- Shell activity monitoring:
  - `cmd.exe`
  - PowerShell / `pwsh`
  - Windows Terminal
  - WSL / `bash`

### network activity
- Live socket connections  
- Local and remote endpoints  
- Process attribution  

### filesystem monitoring
- Recursive monitoring of user directories  
- File creation, modification, deletion, and movement events  

### removable media
- USB and volume insertion/removal (via WMI)

### browser activity (read-only)
- Google Chrome  
- Microsoft Edge  
- Mozilla Firefox  

Local history access only.  
**No injection, no hooking.**

### host security snapshot
Collected at startup:
- OS version and architecture  
- System boot time  
- Logged-in users  
- Network interfaces and IP addresses  

---

## design principles

### no kernel components
- No drivers  
- No kernel callbacks  
- No undocumented APIs  

### graceful privilege degradation
- Runs fully as a standard user  
- Automatically unlocks advanced telemetry when elevated  
- Never blocks execution due to missing permissions  

### transparency by design
- Plain-text logs  
- Human-readable output  
- No obfuscation  
- No hidden persistence  

### production-grade stability
- Defensive threading  
- Anti-spam protections  
- GUI-safe queue handling  
- Automatic channel validation  

---

## execution modes

### user mode (default)
- No UAC prompt  
- Safe for all users  
- Suitable for startup execution  
- Collects all telemetry available without elevation  

### administrator (run as admin)
- Enables advanced event channels  
- Allows PowerShell and firewall logging policies  
- Improved Security event log visibility  

### system (recommended for enterprise)
- Full telemetry coverage  
- No UAC prompts  
- Silent background operation  
- Ideal for SOC and continuous monitoring  

---

## recommended deployment (administrators)

Windows does not allow silent elevation for user applications by design.

The **only secure and supported method** to run Windows Watchdog with full privileges at startup is via a **Scheduled Task**.

This is the same execution model used by:
- Microsoft Defender  
- Sysmon  
- EDR agents  

### create a scheduled task (system, silent)

```powershell
$exePath = "C:\Program Files\Watchdog\Watchdog.exe"

schtasks /create `
  /tn "WindowsWatchdog" `
  /tr "`"$exePath`"" `
  /sc onlogon `
  /ru SYSTEM `
  /rl HIGHEST `
  /f
