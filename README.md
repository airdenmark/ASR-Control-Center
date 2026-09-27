# ASR Control Center

A management GUI built with Python and CustomTkinter designed to configure, monitor, and manage Windows Defender Attack Surface Reduction (ASR) rules, advanced security settings, and critical Windows Group Policies.

![App Preview](App_preview.png)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

- **Full 17-Rule ASR Management:** Easily toggle and configure all official Microsoft Attack Surface Reduction rules.
- **Operational Mode Control:** Switch rules effortlessly between **Block**, **Audit**, **Warn**, and **Disabled** states.
- **Predefined Security Profiles:** Quick-apply safe, enhanced, developer, or macro-friendly security templates.
- **Advanced Defender Settings:** Manage Controlled Folder Access, Network Protection, PUA protection, and cloud-delivered protection.
- **Group Policy Hardening:** Quickly apply or revert critical registry security tweaks (such as disabling `AlwaysInstallElevated` and enforcing UAC).
- **Activity Logging & Export:** Keep track of applied modifications with built-in log rotation and JSON configuration export/import tools.

---

### Important Prerequisites & Caveats

A few things to be aware of before enabling ASR rules:

* **Windows Edition:** Requires Windows 10/11 Pro, Enterprise, or Education, rules are silently ignored on Home edition with no warning.
* **Active Antivirus:** Windows Defender must be your primary, active AV. If you use a third-party antivirus, ASR rules will not function regardless of configuration.
* **Real-time & Cloud Protection:** Real-time protection must be enabled. Additionally, certain rules (such as blocking untrusted executables by prevalence) require Cloud-Delivered Protection to be active.
* **Administrator Privileges:** Modifying ASR configurations requires full administrative rights on the system.
* **Domain Policies:** On domain-joined machines, local settings may be overridden by organizational Group Policy or Intune policies.
* **Recommended Testing:** Use **Audit** mode first to monitor activity in the logs before switching rules to **Block** mode, ensuring your daily applications are not affected.
* **Exclusions:** If a rule blocks a legitimate tool or workflow, you can configure exclusions via Windows Security or PowerShell.

---

## Download & Usage Options

Visit the **[Releases](../../releases)** section to download the application:

* **Direct Executable (`ASR-ControlCenter.exe`)** - Download and right-click to select **Run as Administrator**. No extraction or Python installation required.
* **ZIP Archive (`ASR-ControlCenter.zip`)** - Contains the standalone `.exe` inside a compressed archive. Recommended if your browser or network blocks direct `.exe` downloads.

## For Developers
If you prefer to run or compile the source code directly:
1. Ensure Python 3.8+ is installed.
2. Install the required UI library: `pip install customtkinter`
3. Run `ASR-ControlCenter.py` with administrative privileges.

## Disclaimer
This tool modifies advanced Windows security policies and registry keys. While the profiles are designed to be safe, applying strict ASR rules may interfere with some legacy applications or Office macros. Please review the rules before applying them. Use at your own risk.
