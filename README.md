<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage  
Detection of Unauthorized TOR Browser Installation and Use on Workstation: **vm-test-zedd**

## Platforms and Tools Used
- Microsoft Defender for Endpoint (MDE)
- Microsoft Azure (Windows 10 VM)
- Kusto Query Language (KQL)
- Tor Browser

---

## Scenario Overview

Recent threat intelligence and internal reports raised concerns that labusers may be using the Tor Browser to circumvent organizational security controls. Indicators included encrypted traffic to known Tor entry nodes and conversations suggesting attempts to access restricted websites during work hours. This hunt aimed to detect unauthorized Tor usage and assess the scope of impact.

---

## IoC-Based Threat Hunting Plan

- Search `DeviceFileEvents` for Tor-related file activity (`tor.exe`, `firefox.exe`, etc.)
- Investigate `DeviceProcessEvents` for signs of installation or browser launch
- Review `DeviceNetworkEvents` for traffic on well-known Tor ports

---

## Investigation Steps

### 📁 1. File Event Analysis

Initial file event queries revealed that user **labuser** on `vm-test-zedd` downloaded and interacted with several Tor-related files. Activity began at `2025-05-22T14:36:21.865Z`, including creation of a file named `tor-shopping-list.txt`.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "vm-test-zedd"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "labuser"
| where Timestamp >= datetime(2025-05-22T14:36:21.8652838Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![1m](https://github.com/user-attachments/assets/2721a36b-a62c-4fa5-94e4-5b8f2348cf63)


---

### 🧩 2. Tor Installer Execution

Process event logs confirmed that the executable `tor-browser-windows-x86_64-portable-14.5.2.exe` was run by **labuser** from the Downloads folder at `2025-05-22T14:39:32.908Z`, using a silent install flag.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-test-zedd"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.2.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![2](https://github.com/user-attachments/assets/b82f417a-1793-4660-acdf-a21085921ecf)


---

### 🦊 3. Browser Launch Confirmation

Further analysis of `DeviceProcessEvents` verified the launch of `firefox.exe` and `tor.exe` by **labuser**, indicating successful initialization of the Tor Browser environment around `2025-05-22T14:44:31.841Z`.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-test-zedd"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![3](https://github.com/user-attachments/assets/b2d934b6-8b62-42b6-8966-bcf8e35530c3)

---

### 🌐 4. Network Connection via Tor

At `2025-05-22T14:44:59.880Z`, `tor.exe` successfully connected to a known Tor node at IP `77.174.62.158` over port `9001`, originating from the Tor Browser installation path.

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "vm-test-zedd"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001","9030","9040","9050","9051","9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![4](https://github.com/user-attachments/assets/5e4af8af-0d47-4c51-b026-f0b1c59fae09)


---

## 📅 Timeline of Events – May 22, 2025

| Time (UTC)       | Event                  | Description |
|------------------|------------------------|-------------|
| **14:36:21**     | File Events Triggered   | Tor-related files created, including `tor-shopping-list.txt`. |
| **14:39:32**     | Silent Installer Run    | Executed `tor-browser-windows-x86_64-portable-14.5.2.exe`. |
| **14:44:31**     | Tor Browser Launched    | Firefox and Tor processes initiated from install folder. |
| **14:44:59**     | Network Connection Made | Connection to `77.174.62.158:9001` using `tor.exe`. |

---

## 🧾 Summary of Findings

On **May 22, 2025**, user **labuser** downloaded and installed the Tor Browser on the virtual machine **vm-test-zedd**. Installation was silently performed, followed by successful launch and connection to a known Tor relay node. The presence of a `tor-shopping-list.txt` file further suggests intent and premeditation.

---

## 🔐 Response Actions

- Device `vm-test-zedd` was isolated via Microsoft Defender for Endpoint.
- The user's manager was informed for further disciplinary review.
- Tor activity logs were retained and secured for compliance auditing.

---
