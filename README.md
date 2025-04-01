<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/aktran321/threat-hunting-scenario-tor/tree/main)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "andy" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a shortcut link called `tor-shopping-list.txt.lnk` on the desktop at `2025-03-29T07:14:48.7302544Z`. These events began at `2025-03-29T07:04:16.2491188Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm"
| where InitiatingProcessAccountName == "andy"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-29T07:04:16.2491188Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/dfe1c47c-e6b7-4c13-8617-0445fdba0d11">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-03-29T07:04:16.2491188Z`, an employee on the "vm" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "vm"
| where InitiatingProcessAccountName == "andy"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.8.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/1be06354-e262-46de-be7d-010f8a073794">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "andy" actually opened the TOR browser. There was evidence that they did open it at `2025-03-29T07:06:32.9484285Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm"
| where InitiatingProcessAccountName == "andy"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5464759a-0e6a-45c2-a24a-a68c3e8d0a00">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-29T07:06:48.7049581Z`, an employee on the "vm" device successfully established a connection to the remote IP address `94.23.70.32` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/bd17f291-1cb8-4e40-a5fe-ade398262c7b">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-29T07:04:16.2491188Z`
- **Event:** The user "andy" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\andy\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-29T07:04:16.2491188Z`
- **Event:** The user "andy" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\andy\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-29T07:06:32.9484285Z`
- **Event:** User "andy" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\andy\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-29T07:06:48.7049581Z`
- **Event:** A network connection to IP `94.23.70.32` on port `9001` by user "andy" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\andy\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-29T07:06:49.4106031Z` - Connected to `94.23.70.32` on port `9001`.
  - `2025-03-29T07:06:58.0900818Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "andy" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-29T07:14:48.7302544Z`
- **Event:** The user "andy" created a shortcut link named `tor-shopping-list.txt.lnk` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\andy\Desktop\tor-shopping-list.txt.lnk`

---

## Summary

The user "andy" on the "vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt.lnk`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of a "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `vm` by the user `andy`. The device was isolated, and the user's direct manager was notified.

---
