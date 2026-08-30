"""
ASR Control Center — v2 (Final)
Full 17-rule ASR management with Audit/Warn modes, Advanced Defender
settings, Group Policy shortcuts, Export/Import, and activity logging.

v2 improvements:
  - run_ps captures stderr; errors reported via coloured toasts and log
  - Group Policy tab reads current registry state on load
  - Profile mode selector (Block / Audit / Warn) applied to all profiles
  - _apply_adv only writes settings that changed since last load
  - _reload_log called after every apply action
  - Batch launcher uses py launcher instead of hardcoded Python path
  - Dummy GUID workaround for systems rejecting empty arrays
  - Status count and profile detection ignore disabled (action=0) rules
  - Log rotation (keeps last 1000 lines)
  - User-friendly toast messages for 'Off' / no rules
"""

import os, sys

# ── Fix Tcl/Tk path BEFORE importing tkinter ─────────────────────────────────
def _fix_tcl_paths():
    python_dir = os.path.dirname(sys.executable)
    tcl_dir = os.path.join(python_dir, "tcl")
    if not os.path.isdir(tcl_dir):
        return
    for entry in os.listdir(tcl_dir):
        full = os.path.join(tcl_dir, entry)
        if entry.startswith("tcl") and os.path.isfile(os.path.join(full, "init.tcl")):
            os.environ["TCL_LIBRARY"] = full
        if entry.startswith("tk") and os.path.isdir(full):
            os.environ["TK_LIBRARY"] = full

_fix_tcl_paths()

import subprocess, json, ctypes, datetime, threading
from pathlib import Path
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog

# ── Resource path for PyInstaller ────────────────────────────────────────────
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

ICON_PATH = resource_path("icon.ico")

# ── Admin elevation ───────────────────────────────────────────────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def elevate():
    script = os.path.abspath(sys.argv[0])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}"', None, 1
    )
    sys.exit()

# ── Colour palette ────────────────────────────────────────────────────────────
C = {
    "bg":       "#0F1117",
    "surface":  "#161B27",
    "surface2": "#1E2535",
    "border":   "#252D42",
    "accent":   "#3B82F6",
    "accent2":  "#60A5FA",
    "text":     "#E2E8F0",
    "muted":    "#94A3B8",  # Slightly brightened muted text for dark theme legibility
    "green":    "#22C55E",
    "amber":    "#F59E0B",
    "orange":   "#F97316",
    "red":      "#EF4444",
    "purple":   "#A78BFA",
}

# ── Global Typography Configurations ─────────────────────────────────────────
FONT_MAIN = "Segoe UI"
FONT_MONO = "Consolas"

# ── Mode maps ─────────────────────────────────────────────────────────────────
MODES      = {"Disabled": 0, "Block": 1, "Audit": 2, "Warn": 6}
MODE_NAMES = {0: "Disabled", 1: "Block", 2: "Audit", 6: "Warn"}
MODE_COLOR = {
    "Disabled": C["muted"],
    "Block":    C["green"],
    "Audit":    C["accent2"],
    "Warn":     C["orange"],
}

# ── ASR Rule definitions (full Microsoft set) ─────────────────────────────────
ASR_RULES = [
    {
        "id":   "56a863a9-875e-4185-98a7-b882c64b5ce5",
        "name": "Block abuse of vulnerable signed drivers",
        "desc": "Prevents apps from writing a vulnerable signed driver to disk. "
                "Stops BYOVD attacks where malware uses a legitimate but vulnerable "
                "driver to gain kernel-level access and disable security tools.",
        "pros": "Blocks ransomware from disabling Defender via kernel exploits. "
                "Strongly recommended by Microsoft.",
        "cons": "May block older hardware driver installers on legacy systems.",
        "dev":  "Safe for most developers unless installing test-signed kernel drivers.",
        "risk": "medium",
        "profiles": ["safe", "enhanced", "developer"],
    },
    {
        "id":   "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
        "name": "Block Adobe Reader from creating child processes",
        "desc": "Stops Adobe Reader and Acrobat from launching other programs. "
                "PDFs exploiting Reader vulnerabilities commonly use this vector "
                "to drop and execute malware payloads.",
        "pros": "Major reduction in PDF-based malware. PDFs should never spawn processes.",
        "cons": "Breaks PDFs that open browsers or external tools via embedded actions.",
        "dev":  "No impact for most developers.",
        "risk": "medium",
        "profiles": ["safe", "enhanced"],
    },
    {
        "id":   "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "name": "Block all Office apps from creating child processes",
        "desc": "Word, Excel, and PowerPoint cannot spawn cmd.exe, PowerShell, "
                "wscript.exe, or any other child process. One of the most commonly "
                "abused Office behaviours in macro-based attacks.",
        "pros": "Blocks ~90% of macro-based malware delivery. Critical protection.",
        "cons": "Breaks macros that automate external tools or run shell commands.",
        "dev":  "HIGH IMPACT: set to Audit first if you automate Office with scripts.",
        "risk": "high",
        "profiles": ["safe", "enhanced"],
    },
    {
        "id":   "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        "name": "Block credential stealing from Windows LSASS",
        "desc": "Locks LSASS (Local Security Authority) memory from being read "
                "by other processes. Tools like Mimikatz harvest credentials "
                "directly from LSASS memory after gaining admin access.",
        "pros": "Directly counters Mimikatz and similar credential-dumping tools. "
                "Near-zero user impact.",
        "cons": "Very rare conflicts with legacy security scanners or old backup agents.",
        "dev":  "Safe to enable in all scenarios.",
        "risk": "high",
        "profiles": ["safe", "enhanced", "developer", "macro"],
    },
    {
        "id":   "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
        "name": "Block executable content from email & webmail",
        "desc": "Prevents Outlook and browser-based webmail from launching executables "
                "(.exe, .js, .ps1, .vbs) directly from downloaded attachments. "
                "One of the top initial-access vectors in phishing attacks.",
        "pros": "Instantly stops phishing payload delivery. High impact, low friction.",
        "cons": "Users must save attachments to disk before running. Minor inconvenience.",
        "dev":  "No impact for developers.",
        "risk": "high",
        "profiles": ["safe", "enhanced", "developer", "macro"],
    },
    {
        "id":   "01443614-cd74-433a-b99e-2ecdc07bfc25",
        "name": "Block untrusted executables (by prevalence)",
        "desc": "Only allows executables widely seen in Microsoft cloud telemetry, "
                "signed by trusted publishers, or explicitly whitelisted. Unknown "
                "or rare binaries are blocked before they can run.",
        "pros": "Powerful zero-day protection — stops new unknown malware before "
                "signatures exist.",
        "cons": "Will block custom builds, internal unsigned tools, and new software.",
        "dev":  "VERY HIGH IMPACT: use Audit mode or add folder exclusions for build output.",
        "risk": "high",
        "profiles": ["enhanced"],
    },
    {
        "id":   "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
        "name": "Block execution of potentially obfuscated scripts",
        "desc": "Detects and blocks heavily obfuscated JavaScript, VBScript, and "
                "PowerShell — a hallmark of malware attempting to hide its code "
                "from signature-based detection engines.",
        "pros": "Catches malware that encodes or obfuscates its payload to evade AV.",
        "cons": "May flag minified or packed legitimate JavaScript and build scripts.",
        "dev":  "Test your build scripts in Audit mode — minified JS can trigger this.",
        "risk": "medium",
        "profiles": ["enhanced"],
    },
    {
        "id":   "d3e037e1-3eb8-44c8-a917-57927947596d",
        "name": "Block JS/VBScript from launching downloaded content",
        "desc": "Prevents JavaScript and VBScript files from downloading and executing "
                "additional payloads. This breaks the classic drive-by download "
                "attack chain used in watering-hole attacks.",
        "pros": "Breaks the most common drive-by download attack pattern.",
        "cons": "Breaks legacy web-based software installers that use .js/.vbs launchers.",
        "dev":  "Low impact for most development workflows.",
        "risk": "medium",
        "profiles": ["safe", "enhanced"],
    },
    {
        "id":   "3b576869-a4ec-4529-8536-b80a7769e899",
        "name": "Block Office apps from creating executable content",
        "desc": "Prevents Word, Excel, and PowerPoint from writing executable files "
                "(.exe, .dll, .bat) to disk. A core technique used by macro-based "
                "droppers to install ransomware and other malware.",
        "pros": "Stops macro droppers — a very common ransomware delivery method.",
        "cons": "Breaks Office solutions that legitimately generate or compile executables.",
        "dev":  "Disable if you develop VBA solutions that produce output executable files.",
        "risk": "high",
        "profiles": ["safe", "enhanced"],
    },
    {
        "id":   "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
        "name": "Block Office apps from injecting into other processes",
        "desc": "Prevents Office applications from injecting shellcode or DLLs into "
                "other running processes — a technique used in advanced Office exploits "
                "to execute code under the cover of a trusted process.",
        "pros": "Stops sophisticated Office-based code injection used in targeted attacks.",
        "cons": "Some third-party Office add-ins and accessibility tools may break.",
        "dev":  "Generally safe. Test any Office COM add-ins you rely on.",
        "risk": "high",
        "profiles": ["safe", "enhanced", "macro"],
    },
    {
        "id":   "26190899-1602-49e8-8b27-eb1d0a1ce869",
        "name": "Block Office communication apps from child processes",
        "desc": "Prevents Outlook and other Office communication apps from spawning "
                "child processes. A common post-exploitation escalation path used "
                "by phishing campaigns that target Outlook via malicious attachments.",
        "pros": "Closes a frequently exploited Outlook escalation path.",
        "cons": "May affect Outlook add-ins that legitimately launch helper processes.",
        "dev":  "Low impact for most developers.",
        "risk": "medium",
        "profiles": ["safe", "enhanced", "developer", "macro"],
    },
    {
        "id":   "e6db77e5-3df2-4cf1-b95a-636979351e5b",
        "name": "Block persistence through WMI event subscription",
        "desc": "Prevents malware from using WMI event subscriptions to survive "
                "reboots — a sophisticated fileless persistence technique used by "
                "advanced threat actors to remain on a system without dropping files.",
        "pros": "Blocks a hard-to-detect persistence method used in APT campaigns.",
        "cons": "May affect enterprise monitoring tools that use WMI subscriptions.",
        "dev":  "Safe for most development environments.",
        "risk": "medium",
        "profiles": ["safe", "enhanced", "developer", "macro"],
    },
    {
        "id":   "d1e49aac-8f56-4280-b9ba-993a6d77406c",
        "name": "Block process creation from PSExec and WMI commands",
        "desc": "Blocks processes spawned via PSExec or WMI commands — tools heavily "
                "used during ransomware campaigns for lateral movement across a network "
                "after initial compromise.",
        "pros": "Significantly slows or stops ransomware spread across a network.",
        "cons": "Breaks remote administration workflows that depend on PSExec or WMI.",
        "dev":  "HIGH IMPACT if you use PSExec or WMI for remote management — set Audit.",
        "risk": "high",
        "profiles": ["enhanced"],
    },
    {
        "id":   "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
        "name": "Block untrusted and unsigned processes from USB",
        "desc": "Blocks unsigned or untrusted executables from running directly "
                "off USB drives. Mitigates physical-access attacks, malicious "
                "USB drops, and accidental autorun of infected removable media.",
        "pros": "Mitigates 'evil USB' attacks and rogue USB drops.",
        "cons": "Inconvenient if you regularly run unsigned portable apps from USB.",
        "dev":  "Disable if you run development tools or scripts directly from USB.",
        "risk": "medium",
        "profiles": ["enhanced"],
    },
    {
        "id":   "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
        "name": "Block use of copied or impersonated system tools",
        "desc": "Prevents abuse of copied or renamed Windows system binaries (lolbins). "
                "Attackers copy cmd.exe or powershell.exe to unexpected locations to "
                "bypass application control and allowlisting rules.",
        "pros": "Blocks living-off-the-land attacks that rename system tools to evade detection.",
        "cons": "Rare false positives with some packaging or virtualisation tools.",
        "dev":  "Generally safe for standard development environments.",
        "risk": "medium",
        "profiles": ["enhanced"],
    },
    {
        "id":   "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
        "name": "Block Win32 API calls from Office macros",
        "desc": "Prevents VBA macros from calling Win32 APIs via Declare statements. "
                "This blocks a key technique for running shellcode or loading malicious "
                "DLLs from within an Office macro without dropping a separate file.",
        "pros": "Stops dangerous VBA that loads shellcode via Windows API calls.",
        "cons": "Breaks advanced macros that use Declare statements for legitimate automation.",
        "dev":  "Disable if you develop VBA macros that use Win32 Declare statements.",
        "risk": "high",
        "profiles": ["enhanced"],
    },
    {
        "id":   "c1db55ab-c21a-4637-bb3f-a12568109d35",
        "name": "Use advanced protection against ransomware",
        "desc": "Applies extra heuristic-based detection targeting ransomware-like "
                "behaviours such as rapid file modification, shadow copy deletion, "
                "and volume encryption patterns.",
        "pros": "Strong additional anti-ransomware layer on top of standard signatures.",
        "cons": "May flag legitimate encryption tools, compression tools, or backup software.",
        "dev":  "Test your backup and encryption tools — some can trigger this rule.",
        "risk": "medium",
        "profiles": ["safe", "enhanced"],
    },
]

# ── Profile definitions ───────────────────────────────────────────────────────
PROFILES = {
    "Safe": {
        "ids":   [r["id"] for r in ASR_RULES if "safe" in r["profiles"]],
        "color": "#1A6B3C",
        "desc":  "Core protection, minimal workflow disruption.",
    },
    "Enhanced": {
        "ids":   [r["id"] for r in ASR_RULES if "enhanced" in r["profiles"]],
        "color": "#1A5FA8",
        "desc":  "Full ruleset. Recommended for most users.",
    },
    "Macro-Friendly": {
        "ids":   [r["id"] for r in ASR_RULES if "macro" in r["profiles"]],
        "color": "#7A5800",
        "desc":  "Core protection, permits Office macro workflows.",
    },
    "Developer": {
        "ids":   [r["id"] for r in ASR_RULES if "developer" in r["profiles"]],
        "color": "#5B3090",
        "desc":  "Minimal set, avoids conflicts with build tools.",
    },
    "Off": {
        "ids":   [],
        "color": "#7A1A1A",
        "desc":  "All rules disabled. Not recommended.",
    },
}

# ── Advanced Defender settings ────────────────────────────────────────────────
ADV_SETTINGS = [
    {
        "name":   "Controlled Folder Access",
        "desc":   "Protects Documents, Desktop, and Pictures from unauthorized "
                  "changes. Only trusted apps can modify files in protected folders. "
                  "Highly effective against ransomware encryption.",
        "pros":   "Directly prevents ransomware from encrypting your personal files.",
        "cons":   "Legitimate apps may need to be manually approved. Can be disruptive.",
        "ps_get": "EnableControlledFolderAccess",
        "ps_set": "EnableControlledFolderAccess",
        "modes":  {"Disabled": 0, "Enabled": 1, "Audit": 2},
    },
    {
        "name":   "Network Protection",
        "desc":   "Blocks outbound connections to known malicious IPs, domains, and "
                  "URLs at the network driver level. Requires cloud protection active.",
        "pros":   "Stops C2 callbacks and malware downloads at the network layer.",
        "cons":   "Requires cloud protection. Some false positives on poorly rated sites.",
        "ps_get": "EnableNetworkProtection",
        "ps_set": "EnableNetworkProtection",
        "modes":  {"Disabled": 0, "Enabled": 1, "Audit": 2},
    },
    {
        "name":   "PUA Protection (Potentially Unwanted Apps)",
        "desc":   "Blocks software flagged as potentially unwanted — adware, bundled "
                  "installers, browser toolbars, and cryptocurrency miners.",
        "pros":   "Keeps the system clean from bloatware and aggressive adware.",
        "cons":   "Some grey-area tools (certain optimisers) may be blocked.",
        "ps_get": "PUAProtection",
        "ps_set": "PUAProtection",
        "modes":  {"Disabled": 0, "Enabled": 1, "Audit": 2},
    },
    {
        "name":   "Cloud-delivered Protection (MAPS)",
        "desc":   "Sends file metadata to Microsoft cloud for rapid threat intelligence. "
                  "Enables near-real-time detection of new threats before local "
                  "signature databases are updated.",
        "pros":   "Dramatically faster detection of new and emerging threats.",
        "cons":   "Requires internet access. Sends file hashes/metadata to Microsoft.",
        "ps_get": "MAPSReporting",
        "ps_set": "MAPSReporting",
        "modes":  {"Disabled": 0, "Basic": 1, "Advanced": 2},
    },
]

# ── Group Policy tweaks ───────────────────────────────────────────────────────
GP_TWEAKS = [
    {
        "name":     "Disable AlwaysInstallElevated",
        "desc":     "Ensures MSI packages do not install with SYSTEM privileges by "
                    "default. AlwaysInstallElevated=1 is a classic privilege escalation "
                    "vector — any user can install software as SYSTEM.",
        "pros":     "Closes a well-known privilege escalation path. No legitimate use case.",
        "cons":     "None — this should always be disabled.",
        "category": "Privilege Control",
        "key":      "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        "value":    "AlwaysInstallElevated",
        "data":     0, "type": "DWORD",
    },
    {
        "name":     "Enforce UAC (User Account Control)",
        "desc":     "Ensures UAC prompts are active for all privilege elevation requests. "
                    "Disabling UAC silently grants admin rights to all processes, "
                    "removing a fundamental Windows security boundary.",
        "pros":     "Core security boundary — should never be disabled.",
        "cons":     "None — UAC-enabled is always the correct state.",
        "category": "Privilege Control",
        "key":      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "value":    "EnableLUA",
        "data":     1, "type": "DWORD",
    },
    {
        "name":     "Disable WinRM Basic Authentication",
        "desc":     "Prevents Windows Remote Management from accepting cleartext "
                    "Basic authentication. Credentials sent via Basic auth are Base64 "
                    "encoded — trivially decoded in a MITM scenario.",
        "pros":     "Blocks credential interception over WinRM in network attacks.",
        "cons":     "Breaks scripts relying on Basic auth for WinRM remote management.",
        "category": "Network Security",
        "key":      "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
        "value":    "AllowBasic",
        "data":     0, "type": "DWORD",
    },
    {
        "name":     "Enable DNS-over-HTTPS (DoH)",
        "desc":     "Forces the Windows DNS client to use encrypted DNS queries, "
                    "preventing ISP-level DNS snooping, DNS hijacking, and some "
                    "network-based surveillance techniques.",
        "pros":     "Encrypts DNS traffic, reducing MITM and surveillance exposure.",
        "cons":     "Requires a DoH-capable resolver configured in Network Settings.",
        "category": "Network Security",
        "key":      "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
        "value":    "DoHPolicy",
        "data":     2, "type": "DWORD",
    },
    {
        "name":     "Restrict Command Prompt (non-admins)",
        "desc":     "Limits cmd.exe access for standard users. Interactive shell is "
                    "blocked, though scripts can still run. Reduces attack surface "
                    "for script-based lateral movement by non-admin accounts.",
        "pros":     "Reduces risk from script-based attacks by non-privileged users.",
        "cons":     "Breaks workflows relying on cmd.exe for standard user shortcuts.",
        "category": "Shell Hardening",
        "key":      "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "value":    "DisableCMD",
        "data":     2, "type": "DWORD",
    },
    {
        "name":     "Set PowerShell Execution Policy (RemoteSigned)",
        "desc":     "Requires local scripts to be signed, and downloaded scripts to be "
                    "signed by a trusted publisher. Prevents accidental or malicious "
                    "execution of unsigned remote PowerShell payloads.",
        "pros":     "Reduces risk from unsigned downloaded PowerShell scripts.",
        "cons":     "Breaks unsigned local scripts. A determined attacker can bypass this.",
        "category": "Shell Hardening",
        "key":      "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
        "value":    "ExecutionPolicy",
        "data":     "RemoteSigned", "type": "SZ",
    },
]

LOG_PATH = Path.home() / "Desktop" / "ASR-Log.txt"

# ── PowerShell helpers ────────────────────────────────────────────────────────
def run_ps(cmd):
    """Run a PowerShell command. Returns (stdout, stderr, returncode)."""
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NO_WINDOW

    r = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass",
         "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True,
        creationflags=creationflags
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode

def run_ps_out(cmd):
    """Convenience wrapper — returns only stdout for read operations."""
    out, _, _ = run_ps(cmd)
    return out

def get_asr_state():
    out = run_ps_out(
        "Get-MpPreference | "
        "Select-Object AttackSurfaceReductionRules_Ids, "
        "AttackSurfaceReductionRules_Actions | ConvertTo-Json"
    )
    try:
        data = json.loads(out) if out else {}
    except:
        return {}
    ids  = data.get("AttackSurfaceReductionRules_Ids")  or []
    acts = data.get("AttackSurfaceReductionRules_Actions") or []
    if isinstance(ids,  str):           ids  = [ids]
    if isinstance(acts, (int, float)):  acts = [int(acts)]
    return {str(i).upper(): int(a) for i, a in zip(ids, acts)}

def set_asr_rules(state_dict):
    """Apply ASR rules. Returns (success, error_message)."""
    if not state_dict:
        dummy = "00000000-0000-0000-0000-000000000000"
        _, err, rc = run_ps(
            f"Set-MpPreference -AttackSurfaceReductionRules_Ids @('{dummy}') "
            f"-AttackSurfaceReductionRules_Actions @(0)"
        )
    else:
        ids_s = ",".join(f'"{i}"' for i in state_dict)
        act_s = ",".join(str(v) for v in state_dict.values())
        _, err, rc = run_ps(
            f"Set-MpPreference "
            f"-AttackSurfaceReductionRules_Ids @({ids_s}) "
            f"-AttackSurfaceReductionRules_Actions @({act_s})"
        )
    return rc == 0, err

def get_adv_state():
    fields = ",".join(s["ps_get"] for s in ADV_SETTINGS)
    out = run_ps_out(f"Get-MpPreference | Select-Object {fields} | ConvertTo-Json")
    try:
        return json.loads(out) if out else {}
    except:
        return {}

def write_reg(key, value, data, reg_type="DWORD"):
    """Write a registry value to HKLM. Returns (success, error_message)."""
    try:
        import winreg
        type_map = {"DWORD": winreg.REG_DWORD, "SZ": winreg.REG_SZ}
        k = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE, key, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        )
        winreg.SetValueEx(k, value, 0, type_map.get(reg_type, winreg.REG_DWORD), data)
        winreg.CloseKey(k)
        return True, ""
    except Exception as e:
        return False, str(e)

def delete_reg(key, value):
    """Delete a registry value from HKLM (reverts a GP tweak)."""
    try:
        import winreg
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, key, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        )
        winreg.DeleteValue(k, value)
        winreg.CloseKey(k)
        return True, ""
    except FileNotFoundError:
        return True, ""
    except Exception as e:
        return False, str(e)

def read_reg(key, value):
    """Read a registry value from HKLM. Returns the value or None if absent."""
    try:
        import winreg
        k = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, key, 0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
        val, _ = winreg.QueryValueEx(k, value)
        winreg.CloseKey(k)
        return val
    except Exception:
        return None

def get_gp_state():
    return {i: read_reg(t["key"], t["value"]) for i, t in enumerate(GP_TWEAKS)}

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.exists():
            lines = LOG_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
            if len(lines) >= 1000:
                LOG_PATH.write_text("".join(lines[-900:]), encoding="utf-8")
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts}  {msg}\n")
    except Exception:
        pass

# ── App ───────────────────────────────────────────────────────────────────────
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ASR Control Center")
        self.geometry("1220x840")
        self.minsize(960, 700)
        self.configure(fg_color=C["bg"])
        ctk.set_appearance_mode("dark")

        if os.path.exists(ICON_PATH):
            self.after(200, lambda: self.iconbitmap(ICON_PATH))

        self._rule_vars    = {}
        self._rule_cards   = {}
        self._adv_vars     = {}
        self._gp_vars      = {}
        self._asr_state    = {}
        self._adv_loaded   = {}
        self._profile_mode = tk.StringVar(value="Block")
        self._status_count   = tk.StringVar(value="…")
        self._status_profile = tk.StringVar(value="")

        self._build_ui()
        self.after(300, lambda: threading.Thread(
            target=self._load_all, daemon=True).start())

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        sidebar = ctk.CTkFrame(self, width=220, fg_color=C["surface"], corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self._build_sidebar(sidebar)

        main = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        main.pack(side="left", fill="both", expand=True)
        self._build_main(main)

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self, p):
        logo = ctk.CTkFrame(p, fg_color=C["surface2"], corner_radius=0, height=72)
        logo.pack(fill="x")
        logo.pack_propagate(False)
        ctk.CTkLabel(logo, text="ASR", font=(FONT_MAIN, 26, "bold"),
                     text_color=C["accent"]).pack(pady=(10, 0))
        ctk.CTkLabel(logo, text="CONTROL CENTER", font=(FONT_MAIN, 9, "bold"),
                     text_color=C["muted"]).pack()

        ctk.CTkLabel(p, text="PROFILES", font=(FONT_MAIN, 11, "bold"),
                     text_color=C["muted"]).pack(pady=(18, 4))

        ctk.CTkLabel(p, text="Apply in mode:",
                     font=(FONT_MAIN, 10), text_color=C["muted"]).pack()
        ctk.CTkSegmentedButton(
            p, values=["Block", "Audit", "Warn"],
            variable=self._profile_mode,
            font=(FONT_MAIN, 11),
            fg_color=C["surface2"],
            selected_color=C["accent"],
            unselected_color=C["surface2"],
            selected_hover_color="#2563EB",
            unselected_hover_color=C["border"],
        ).pack(fill="x", padx=12, pady=(4, 10))

        for name, pdata in PROFILES.items():
            ctk.CTkButton(
                p, text=name, height=36,
                fg_color=pdata["color"], hover_color=C["border"],
                font=(FONT_MAIN, 12, "bold"), corner_radius=6,
                command=lambda n=name, d=pdata: self._apply_profile(n, d)
            ).pack(fill="x", padx=12, pady=3)

        ctk.CTkFrame(p, height=1, fg_color=C["border"]).pack(
            fill="x", padx=12, pady=14)

        ctk.CTkButton(
            p, text="▶  Apply ASR Changes", height=40,
            fg_color=C["accent"], hover_color="#2563EB",
            font=(FONT_MAIN, 12, "bold"), corner_radius=6,
            command=self._apply_asr
        ).pack(fill="x", padx=12, pady=3)

        ctk.CTkButton(
            p, text="↺  Refresh", height=34,
            fg_color=C["surface2"], hover_color=C["border"],
            font=(FONT_MAIN, 11, "bold"), corner_radius=6,
            command=lambda: threading.Thread(
                target=self._load_all, daemon=True).start()
        ).pack(fill="x", padx=12, pady=3)

        status = ctk.CTkFrame(p, fg_color=C["surface2"], corner_radius=8)
        status.pack(side="bottom", fill="x", padx=12, pady=16)
        ctk.CTkLabel(status, text="ACTIVE RULES",
                     font=(FONT_MAIN, 10, "bold"), text_color=C["muted"]).pack(pady=(10, 0))
        ctk.CTkLabel(status, textvariable=self._status_count,
                     font=(FONT_MONO, 28, "bold"),
                     text_color=C["green"]).pack()
        ctk.CTkLabel(status, textvariable=self._status_profile,
                     font=(FONT_MAIN, 11, "bold"), text_color=C["muted"]).pack(pady=(0, 12))

        col  = C["green"] if is_admin() else C["red"]
        txt  = "● ADMIN" if is_admin() else "● NOT ADMIN"
        ctk.CTkLabel(p, text=txt, font=(FONT_MONO, 10, "bold"),
                     text_color=col).pack(pady=(0, 6))

    # ── Main tabview ──────────────────────────────────────────────────────────
    def _build_main(self, p):
        self._tabview = ctk.CTkTabview(p, fg_color=C["surface"],
                                       segmented_button_fg_color=C["surface2"],
                                       segmented_button_selected_color=C["accent"],
                                       segmented_button_unselected_color=C["surface2"],
                                       text_color=C["text"])
        
        # Increase tab header font size
        self._tabview._segmented_button.configure(font=(FONT_MAIN, 12, "bold"))
        self._tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        for tab in ["ASR Rules", "Advanced Security", "Group Policy", "Log & Export"]:
            self._tabview.add(tab)

        self._build_asr_tab()
        self._build_adv_tab()
        self._build_gp_tab()
        self._build_log_tab()

    # ── ASR Rules tab ─────────────────────────────────────────────────────────
    def _build_asr_tab(self):
        tab = self._tabview.tab("ASR Rules")

        legend = ctk.CTkFrame(tab, fg_color=C["surface2"], corner_radius=6)
        legend.pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkLabel(legend, text="Modes:", font=(FONT_MAIN, 11, "bold"),
                     text_color=C["muted"]).pack(side="left", padx=(12, 8))
        for mode, color in MODE_COLOR.items():
            ctk.CTkLabel(legend, text=f"● {mode}",
                         font=(FONT_MAIN, 11, "bold"), text_color=color).pack(
                             side="left", padx=8)
        ctk.CTkLabel(legend,
                     text="Audit = logs without blocking  ·  Warn = prompts user",
                     font=(FONT_MAIN, 11), text_color=C["muted"]).pack(
                         side="right", padx=12)

        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=4, pady=4)

        for rule in ASR_RULES:
            self._rule_card(scroll, rule)

    def _rule_card(self, parent, rule):
        rid = rule["id"].upper()
        var = tk.StringVar(value="Disabled")
        self._rule_vars[rid] = var

        risk_color = C["red"] if rule["risk"] == "high" else C["amber"]

        card = ctk.CTkFrame(parent, fg_color=C["surface"], corner_radius=10,
                             border_width=1, border_color=C["border"])
        card.pack(fill="x", pady=6, padx=4)
        self._rule_cards[rid] = card

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(12, 4))

        ctk.CTkLabel(top, text=f"  {rule['risk'].upper()}  ",
                     fg_color=risk_color,
                     text_color="#000" if rule["risk"] == "medium" else C["text"],
                     font=(FONT_MONO, 9, "bold"),
                     corner_radius=4).pack(side="left")

        ctk.CTkLabel(top, text=rule["name"],
                     font=(FONT_MAIN, 13, "bold"),
                     text_color=C["text"]).pack(side="left", padx=10)

        mode_menu = ctk.CTkOptionMenu(
            top, values=list(MODES.keys()), variable=var,
            width=120, height=28,
            fg_color=C["surface2"], button_color=C["border"],
            dropdown_fg_color=C["surface2"],
            text_color=C["text"], font=(FONT_MAIN, 11, "bold"),
            command=lambda v, c=card: self._on_mode_change(v, c)
        )
        mode_menu.pack(side="right")

        # Description with larger size and higher wraplength for wider layout
        ctk.CTkLabel(card, text=rule["desc"],
                     font=(FONT_MAIN, 11), text_color=C["muted"],
                     wraplength=830, justify="left").pack(
                         anchor="w", padx=14, pady=(2, 6))

        # Detail panel
        detail = ctk.CTkFrame(card, fg_color=C["surface2"], corner_radius=6)
        detail.pack(fill="x", padx=14, pady=(0, 6))
        ctk.CTkLabel(detail, text=f"✓  {rule['pros']}",
                     font=(FONT_MAIN, 11), text_color=C["green"],
                     wraplength=810, justify="left").pack(
                         anchor="w", padx=10, pady=(6, 2))
        ctk.CTkLabel(detail, text=f"✗  {rule['cons']}",
                     font=(FONT_MAIN, 11), text_color=C["amber"],
                     wraplength=810, justify="left").pack(
                         anchor="w", padx=10, pady=2)
        ctk.CTkLabel(detail, text=f"⚙  {rule['dev']}",
                     font=(FONT_MAIN, 11), text_color=C["purple"],
                     wraplength=810, justify="left").pack(
                         anchor="w", padx=10, pady=(2, 6))

        # GUID
        ctk.CTkLabel(card, text=rule["id"],
                     font=(FONT_MONO, 9), text_color=C["border"]).pack(
                         anchor="e", padx=14, pady=(0, 6))

    def _on_mode_change(self, value, card):
        color = MODE_COLOR.get(value, C["border"])
        card.configure(border_color=color if value != "Disabled" else C["border"])

    # ── Advanced Security tab ─────────────────────────────────────────────────
    def _build_adv_tab(self):
        tab = self._tabview.tab("Advanced Security")
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=4, pady=8)

        for i, s in enumerate(ADV_SETTINGS):
            var = tk.StringVar(value="Disabled")
            self._adv_vars[i] = var
            self._adv_card(scroll, s, i, var)

        ctk.CTkButton(
            tab, text="Apply Advanced Security Settings", height=42,
            fg_color="#1A6B3C", hover_color="#145530",
            font=(FONT_MAIN, 12, "bold"), corner_radius=8,
            command=self._apply_adv
        ).pack(fill="x", padx=12, pady=(4, 10))

    def _adv_card(self, parent, setting, idx, var):
        card = ctk.CTkFrame(parent, fg_color=C["surface"], corner_radius=10,
                             border_width=1, border_color=C["border"])
        card.pack(fill="x", pady=6, padx=4)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(12, 4))

        ctk.CTkLabel(top, text=setting["name"],
                     font=(FONT_MAIN, 13, "bold"),
                     text_color=C["text"]).pack(side="left")

        ctk.CTkOptionMenu(
            top, values=list(setting["modes"].keys()), variable=var,
            width=120, height=28,
            fg_color=C["surface2"], button_color=C["border"],
            dropdown_fg_color=C["surface2"],
            text_color=C["text"], font=(FONT_MAIN, 11, "bold")
        ).pack(side="right")

        ctk.CTkLabel(card, text=setting["desc"],
                     font=(FONT_MAIN, 11), text_color=C["muted"],
                     wraplength=830, justify="left").pack(
                         anchor="w", padx=14, pady=(2, 6))

        detail = ctk.CTkFrame(card, fg_color=C["surface2"], corner_radius=6)
        detail.pack(fill="x", padx=14, pady=(0, 10))
        ctk.CTkLabel(detail, text=f"✓  {setting['pros']}",
                     font=(FONT_MAIN, 11), text_color=C["green"],
                     wraplength=810, justify="left").pack(
                         anchor="w", padx=10, pady=(6, 2))
        ctk.CTkLabel(detail, text=f"✗  {setting['cons']}",
                     font=(FONT_MAIN, 11), text_color=C["amber"],
                     wraplength=810, justify="left").pack(
                         anchor="w", padx=10, pady=(2, 6))

    # ── Group Policy tab ──────────────────────────────────────────────────────
    def _build_gp_tab(self):
        tab = self._tabview.tab("Group Policy")
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=4, pady=4)

        warn = ctk.CTkFrame(scroll, fg_color="#2D1F0A", corner_radius=8,
                             border_width=1, border_color=C["amber"])
        warn.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            warn,
            text="⚠  These settings write directly to the registry (HKLM). "
                 "Changes take effect immediately and require administrator rights. "
                 "Toggle the switches you want to apply, then click Apply.",
            font=(FONT_MAIN, 11), text_color=C["amber"],
            wraplength=810, justify="left"
        ).pack(padx=14, pady=10)

        cats = {}
        for t in GP_TWEAKS:
            cats.setdefault(t["category"], []).append(t)

        for cat, tweaks in cats.items():
            ctk.CTkLabel(scroll, text=cat.upper(),
                         font=(FONT_MAIN, 10, "bold"),
                         text_color=C["muted"]).pack(anchor="w", pady=(10, 2), padx=4)
            for tweak in tweaks:
                idx = GP_TWEAKS.index(tweak)
                var = tk.BooleanVar(value=False)
                self._gp_vars[idx] = var
                self._gp_card(scroll, tweak, var)

        ctk.CTkButton(
            tab, text="Apply Selected GP Settings", height=42,
            fg_color="#5B3500", hover_color="#7A4800",
            font=(FONT_MAIN, 12, "bold"), corner_radius=8,
            command=self._apply_gp
        ).pack(fill="x", padx=12, pady=(4, 10))

    def _gp_card(self, parent, tweak, var):
        card = ctk.CTkFrame(parent, fg_color=C["surface"], corner_radius=10,
                             border_width=1, border_color=C["border"])
        card.pack(fill="x", pady=6, padx=4)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(12, 4))
        ctk.CTkLabel(top, text=tweak["name"],
                     font=(FONT_MAIN, 13, "bold"),
                     text_color=C["text"]).pack(side="left")
        ctk.CTkSwitch(top, text="", variable=var, width=46,
                      progress_color=C["amber"],
                      button_color=C["text"]).pack(side="right")

        ctk.CTkLabel(card, text=tweak["desc"],
                     font=(FONT_MAIN, 11), text_color=C["muted"],
                     wraplength=830, justify="left").pack(
                         anchor="w", padx=14, pady=(2, 6))

        detail = ctk.CTkFrame(card, fg_color=C["surface2"], corner_radius=6)
        detail.pack(fill="x", padx=14, pady=(0, 10))
        ctk.CTkLabel(detail, text=f"✓  {tweak['pros']}",
                     font=(FONT_MAIN, 11), text_color=C["green"],
                     wraplength=810, justify="left").pack(
                         anchor="w", padx=10, pady=(6, 2))
        ctk.CTkLabel(detail, text=f"✗  {tweak['cons']}",
                     font=(FONT_MAIN, 11), text_color=C["amber"],
                     wraplength=810, justify="left").pack(
                         anchor="w", padx=10, pady=(2, 6))

    # ── Log & Export tab ──────────────────────────────────────────────────────
    def _build_log_tab(self):
        tab = self._tabview.tab("Log & Export")

        btns = ctk.CTkFrame(tab, fg_color="transparent")
        btns.pack(fill="x", padx=8, pady=8)
        for label, cmd in [
            ("Export Config",  self._export),
            ("Import Config",  self._import),
            ("Open Log File",  self._open_log),
            ("Clear Log",      self._clear_log),
        ]:
            ctk.CTkButton(btns, text=label, width=140, height=36,
                          fg_color=C["surface2"], hover_color=C["border"],
                          font=(FONT_MAIN, 11, "bold"), corner_radius=6,
                          command=cmd).pack(side="left", padx=(0, 8))

        self._log_box = ctk.CTkTextbox(
            tab, fg_color=C["surface"], font=(FONT_MONO, 11),
            text_color=C["text"], corner_radius=8)
        self._log_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._reload_log()

    # ── State loading ─────────────────────────────────────────────────────────
    def _load_all(self):
        asr = get_asr_state()
        adv = get_adv_state()
        gp  = get_gp_state()
        self._asr_state  = asr
        self._adv_loaded = adv
        self.after(0, lambda: self._apply_asr_to_ui(asr))
        self.after(0, lambda: self._apply_adv_to_ui(adv))
        self.after(0, lambda: self._apply_gp_to_ui(gp))

    def _apply_asr_to_ui(self, state):
        for rule in ASR_RULES:
            rid    = rule["id"].upper()
            action = state.get(rid, 0)
            mode   = MODE_NAMES.get(action, "Disabled")
            var    = self._rule_vars.get(rid)
            if var:
                var.set(mode)
            card = self._rule_cards.get(rid)
            if card:
                border = MODE_COLOR.get(mode, C["border"]) if mode != "Disabled" else C["border"]
                card.configure(border_color=border)

        n = sum(1 for a in state.values() if a != 0)
        self._status_count.set(str(n))
        self._detect_profile(state)

    def _apply_adv_to_ui(self, adv):
        mode_names_01 = {0: "Disabled", 1: "Enabled", 2: "Audit"}
        maps_names    = {0: "Disabled", 1: "Basic",   2: "Advanced"}
        for i, s in enumerate(ADV_SETTINGS):
            val = adv.get(s["ps_get"], 0)
            if isinstance(val, float):
                val = int(val)
            if s["ps_get"] == "MAPSReporting":
                name = maps_names.get(val, "Disabled")
            else:
                name = mode_names_01.get(val, "Disabled")
            var = self._adv_vars.get(i)
            if var:
                var.set(name)

    def _apply_gp_to_ui(self, gp_state):
        for idx, tweak in enumerate(GP_TWEAKS):
            var = self._gp_vars.get(idx)
            if var is None:
                continue
            current = gp_state.get(idx)
            if current is None:
                var.set(False)
            else:
                try:
                    already_applied = (str(current).lower() ==
                                       str(tweak["data"]).lower())
                except Exception:
                    already_applied = current == tweak["data"]
                var.set(already_applied)

    def _detect_profile(self, state):
        active = {k for k, v in state.items() if v != 0}
        for pname, pdata in PROFILES.items():
            profile_ids = set(i.upper() for i in pdata["ids"])
            if active == profile_ids:
                self._status_profile.set(pname)
                return
        self._status_profile.set("Custom" if active else "Off")

    # ── Actions ───────────────────────────────────────────────────────────────
    def _apply_asr(self):
        state = {}
        for rule in ASR_RULES:
            rid  = rule["id"].upper()
            mode = self._rule_vars.get(rid, tk.StringVar(value="Disabled")).get()
            val  = MODES.get(mode, 0)
            if val != 0:
                state[rid] = val

        def _worker():
            ok, err = set_asr_rules(state)
            if ok:
                if not state:
                    log("All ASR rules disabled.")
                    self.after(0, lambda: self._toast("All rules disabled."))
                else:
                    log(f"Custom ASR applied — {len(state)} rules")
                    self.after(0, lambda: self._toast(f"{len(state)} rule(s) applied."))
            else:
                msg = err or "Unknown PowerShell error"
                log(f"ERROR applying ASR: {msg}")
                self.after(0, lambda: self._toast(
                    f"Failed: {msg[:60]}", success=False))
            self.after(0, self._load_all)
            self.after(200, self._reload_log)

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_profile(self, name, pdata):
        mode_name = self._profile_mode.get()
        mode_val  = MODES.get(mode_name, 1)

        profile_ids_lower = [i.lower() for i in pdata["ids"]]
        for rule in ASR_RULES:
            rid = rule["id"].upper()
            var = self._rule_vars.get(rid)
            if var:
                var.set(mode_name if rule["id"].lower() in profile_ids_lower
                        else "Disabled")

        state = {i.upper(): mode_val for i in pdata["ids"]}

        def _worker():
            ok, err = set_asr_rules(state)
            if ok:
                log(f"Profile applied: {name} ({mode_name})")
                label = "All rules disabled." if not pdata["ids"] else f"'{name}' applied in {mode_name} mode."
                self.after(0, lambda l=label: self._toast(l))
            else:
                msg = err or "Unknown PowerShell error"
                log(f"ERROR applying profile {name}: {msg}")
                self.after(0, lambda: self._toast(
                    f"Failed: {msg[:60]}", success=False))
            self.after(0, self._load_all)
            self.after(200, self._reload_log)

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_adv(self):
        tasks = []
        for i, s in enumerate(ADV_SETTINGS):
            var = self._adv_vars.get(i)
            if not var:
                continue
            chosen_val = s["modes"].get(var.get(), 0)
            loaded_raw = self._adv_loaded.get(s["ps_get"])
            if loaded_raw is not None:
                loaded_val = int(loaded_raw) if isinstance(loaded_raw, float) else loaded_raw
                if loaded_val == chosen_val:
                    continue
            tasks.append((s, chosen_val))

        def _worker():
            applied, errors = 0, []
            for s, chosen_val in tasks:
                _, err, rc = run_ps(f"Set-MpPreference -{s['ps_set']} {chosen_val}")
                if rc == 0:
                    applied += 1
                else:
                    errors.append(f"{s['name']}: {(err or 'error')[:40]}")

            if errors:
                log(f"Advanced Security — {applied} applied, errors: {'; '.join(errors)}")
                self.after(0, lambda: self._toast(
                    f"{applied} applied, {len(errors)} failed.", success=False))
            else:
                log(f"Advanced Security settings applied ({applied} changed)")
                self.after(0, lambda: self._toast(f"{applied} setting(s) updated."))

            self.after(0, self._load_all)
            self.after(300, self._reload_log)

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_gp(self):
        if not is_admin():
            messagebox.showerror("Admin Required",
                                 "Group Policy settings require administrator rights.")
            return
        applied, reverted, errors = 0, 0, []
        for idx, var in self._gp_vars.items():
            t = GP_TWEAKS[idx]
            if var.get():
                ok, err = write_reg(t["key"], t["value"], t["data"], t["type"])
                if ok:
                    applied += 1
                    log(f"GP applied: {t['name']}")
                else:
                    errors.append(t["name"])
                    log(f"GP FAILED: {t['name']} — {err}")
            else:
                ok, err = delete_reg(t["key"], t["value"])
                if ok:
                    reverted += 1
                    log(f"GP reverted: {t['name']}")
                else:
                    errors.append(t["name"])
                    log(f"GP REVERT FAILED: {t['name']} — {err}")

        if errors:
            self._toast(
                f"{applied} applied, {reverted} reverted, "
                f"{len(errors)} failed: {', '.join(errors)[:40]}", success=False)
        else:
            parts = []
            if applied:  parts.append(f"{applied} applied")
            if reverted: parts.append(f"{reverted} reverted")
            self._toast(", ".join(parts) + "." if parts else "No changes made.")

        threading.Thread(target=self._load_all, daemon=True).start()
        self._reload_log()

    def _export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile="ASR-Export.json"
        )
        if not path:
            return
        clean = {k: v for k, v in self._asr_state.items() if v != 0}
        out = {"ids": list(clean.keys()), "actions": list(clean.values())}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        log(f"Config exported to {path}")
        self._toast("Configuration exported.")

    def _import(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            state = {i.upper(): a for i, a in
                     zip(data["ids"], data["actions"])}
            ok, err = set_asr_rules(state)
            if ok:
                log(f"Config imported from {path}")
                self._toast("Configuration imported.")
            else:
                log(f"Import failed: {err}")
                self._toast(f"Import failed: {err[:60]}", success=False)
            threading.Thread(target=self._load_all, daemon=True).start()
            self._reload_log()
        except Exception as e:
            messagebox.showerror("Import Error", str(e))

    def _reload_log(self):
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        if LOG_PATH.exists():
            self._log_box.insert("end", LOG_PATH.read_text(encoding="utf-8"))
        else:
            self._log_box.insert("end", "(No log entries yet.)")
        self._log_box.configure(state="disabled")
        self._log_box.see("end")

    def _open_log(self):
        if LOG_PATH.exists():
            os.startfile(str(LOG_PATH))
        else:
            messagebox.showinfo("Log", "No log file yet.")

    def _clear_log(self):
        if messagebox.askyesno("Clear Log", "Delete the activity log?"):
            LOG_PATH.unlink(missing_ok=True)
            self._reload_log()

    # ── Toast notification ────────────────────────────────────────────────────
    def _toast(self, msg, success=True):
        color    = C["green"] if success else C["red"]
        duration = 2400 if success else 4000
        t = ctk.CTkToplevel(self)
        t.overrideredirect(True)
        t.attributes("-topmost", True)
        t.configure(fg_color=C["surface2"])
        ctk.CTkLabel(t, text=f"  {msg}  ",
                     font=(FONT_MAIN, 11, "bold"), text_color=color,
                     fg_color=C["surface2"]).pack(padx=16, pady=10)
        t.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        tw, th = t.winfo_width(), t.winfo_height()
        t.geometry(f"+{sw-tw-30}+{sh-th-60}")
        t.after(duration, t.destroy)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    if sys.platform == "win32" and not is_admin():
        elevate()
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()