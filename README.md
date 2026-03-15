# Boromir

Inspired in persistence sniper, Boromir was built from the need to create a timeline of all existing persistencies in a system, so that an analyst is able both to perform a complete analysis and to focus on the red zone of the incident.

![image](https://github.com/skyg4mb/Persistence_Boromir/assets/16138308/68ffaefe-0270-4e1c-af00-f08c1c5fdb53)


# Execution

```
python3 boromir.py [-h] [--version] [--source-evidence SOURCE_EVIDENCE] [--csv-output CSV_OUTPUT] [--timezone TIMEZONE] {action}
```

| Argument | Description |
|---|---|
| `--source-evidence` | Path where the Windows disk image is mounted |
| `--csv-output` | Directory where `boromir.output.csv` will be written |
| `--timezone` | Convert all timestamps to the specified timezone |

# Detected Persistence Techniques

## Registry Run Keys (MITRE T1547.001)
- `Get-Run` — HKLM/HKCU Run key
- `Get-RunOnce` — RunOnce key
- `Get-RunEx` — RunEx key
- `Get-RunOnceEx` — RunOnceEx key

## DLL Injection & Hijacking
- `Get-AppInitDlls` — AppInit_DLLs (MITRE T1546.010). Only reported when `LoadAppInit_DLLs=1`.
- `Get-ServiceDlls` — ServiceDll hijacking via registry Parameters subkey (Hexacorn N.4)
- `Get-GPExtensionDlls` — Group Policy Extension DLLs (DllName value only)
- `Get-CHMHelperDll` — CHM Helper DLL (Hexacorn N.77)
- `Get-HHCtrlHijacking` — hhctrl.ocx COM hijack (Hexacorn N.77)
- `Get-COMHijacking` — HKCU COM object hijacking via `Software\Classes\CLSID\*\InprocServer32` (MITRE T1546.015)
- `Get-NLDPDllOverridePath` — Natural Language Development Platform DLL override (Hexacorn N.98)

## Winlogon & Authentication
- `Get-WinlogonUserinit` — Winlogon Userinit property (MITRE T1547.004)
- `Get-WinlogonShell` — Winlogon Shell property (MITRE T1547.004)
- `Get-WinlogonMPNotify` — Winlogon MPNotify property
- `Get-LsaPackages` — LSA Authentication, Security and Notification Packages (MITRE T1547.002). Filters default Windows values to reduce false positives.

## Boot & Pre-OS
- `Get-BootExecute` — Session Manager BootExecute (MITRE T1542.003). Only non-default entries reported.

## Process & Debugger Hooks
- `Get-ImageFileExecutionOptions` — IFEO Debugger value (MITRE T1546.012)
- `Get-Aedebug` — AeDebug custom debugger (Hexacorn N.4)
- `Get-WerFaultHangs` — WerFault Hangs debugger (Hexacorn N.116)
- `Get-SilentProcessExit` — SilentProcessExit MonitorProcess (Hexacorn N.116)

## Autorun & Startup
- `Get-CmdAutorun` — Command Processor AutoRun key
- `Get-ExplorerLoad` — Explorer Load property
- `Get-StartupPrograms` — Files in user Startup folders (MITRE T1547.001)
- `Get-ActiveSetup` — Active Setup StubPath (Hexacorn N.54). Covers Wow6432Node.
- `Get-Screensaver` — SCRNSAVE.EXE in HKCU Control Panel\Desktop (MITRE T1546.002)

## App Paths & Certificates
- `Get-AppCertDlls` — AppCertDlls (MITRE T1546.009)
- `Get-AppPaths` — App Paths subkeys (Hexacorn N.3)

## Scheduled Tasks & Services
- `Get-ScheduledTasks` — Registry TaskCache + XML files from `Windows\System32\Tasks\` and `SysWOW64\Tasks\` (MITRE T1053.005)
- `Get-WindowsServices` — Windows Services via ControlSet (MITRE T1543.003)

## Logon Scripts
- `Get-UserInitMprScript` — UserInitMprLogonScript environment variable (MITRE T1037.001)
- `Get-TerminalProfileStartOnUserLogin` — Windows Terminal profiles with `startOnUserLogin: true`

# Credits

- @skyg4mb
- @jupyterjones
