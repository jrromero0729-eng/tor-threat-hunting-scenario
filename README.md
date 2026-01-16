# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Louimiah/threat-hunt-scenario-tor/blob/main/threat-hunt-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “internlou” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2025-11-09T00:30:39.2010436Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "internvmwinlou"
| where InitiatingProcessAccountName == "internlou"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-09T00:30:39.2010436Z)
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1572" height="705" alt="image" src="https://github.com/user-attachments/assets/92d202a2-5635-4f20-aad8-18c8a983c7f7" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched DeviceProcessEvents table for any ProcessCommandLinethat contained the string “tor” Based on the logs returned at 2025-11-09T00:33:29.083964Z, the user internlou on the virtual machine internvmwinlou executed firefox.exe from the Tor Browser directory, launching the browser’s main process and triggering a ProcessCreated event as part of the Tor Browser startup sequence.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "internvmwinlou"
| where Timestamp >= datetime(2025-11-09T00:33:29.083964Z)
| where ProcessCommandLine contains "tor"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1773" height="460" alt="image" src="https://github.com/user-attachments/assets/7c92d012-36a3-4453-bda6-80b17bfae90e" />

---

### 3. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searced DeviceNetworkEvents table to see if tor was used to establish a connection using any of the known tor port numbers and discovered that on 2025-11-09T00:33:43.6159469Z, the user internlou on the virtual machine internvmwinlou successfully established a network connection from tor.exe located c:\users\internlou\desktop\tor browser\browser\torbrowser\tor\tor.exe to the remote IP address 5.75.138.100 over port 9001, associated with the URL https://www.p6swwxd2jl4eg2cu.com, indicating that the Tor service had connected to an external relay node. There were also a few other connections to sites over port 443 and 9150.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "internvmwinlou"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where InitiatingProcessAccountName == "internlou"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443", "80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1730" height="417" alt="image" src="https://github.com/user-attachments/assets/2659e2a6-6f06-470b-9c1b-6f8d6e2e0f1b" />


---

## Chronological Event Timeline 

# 1. Tor Browser Installation and File Extraction
**Timestamp:** 2025-11-09 00:30:39 Z  
**Device:** internvmwinlou  
**User:** internlou  

**Summary:**  
The user downloaded and executed the Tor Browser installer. This action generated multiple Tor-related files within the desktop directory, including the Tor Browser folder structure (Tor, Browser, Data, etc.). These file-creation events confirm the initial setup and unpacking of the Tor Browser.

---

# 2. Tor Browser Executed (firefox.exe)
**Timestamp:** 2025-11-09 00:33:29 Z  
**Device:** internvmwinlou  
**User:** internlou  
**Process:** firefox.exe  
**Path:** `C:\Users\InternLou\Desktop\Tor Browser\Browser\firefox.exe`  

**Summary:**  
Roughly three minutes after installation, the user launched the Tor Browser via its integrated Firefox executable. This triggered a ProcessCreated event indicating that the browser interface initialized and prepared to route traffic through the Tor service.

---

# 3. Tor Service Network Connection (tor.exe)
**Timestamp:** 2025-11-09 00:33:43 Z  
**Device:** internvmwinlou  
**User:** internlou  
**Process:** tor.exe  
**Path:** `C:\Users\InternLou\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  
**Remote IP:** 5.75.138.100  
**Remote Port:** 9001  
**URL:** https://www.p6swwxd2jl4eg2cu.com  

**Summary:**  
Immediately after Tor Browser startup, tor.exe initiated an outbound connection to a known Tor relay node using port 9001. This event confirms that the Tor network successfully initialized, establishing an encrypted circuit for anonymous communication. Additional activity on ports 9150 and 443 was also observed—consistent with normal Tor operation.

---

# 4. Post-Use File Creation (tor-shopping-list.txt)
**Timestamp:** 2025-11-09 00:39:26 Z  
**Device:** internvmwinlou  
**User:** internlou  
**File:** tor-shopping-list.txt  
**Path:** `C:\Users\InternLou\Desktop\`  

**Summary:**  
Following network activity, a text file named *tor-shopping-list.txt* appeared on the desktop. This indicates user interaction after the Tor session, possibly a document saved during or after browsing while using the Tor Browser.

---

## Summary

Between 2025-11-09 00:30:39 Z and 2025-11-09 00:39:26 Z, the user internlou on device internvmwinlou installed the Tor Browser and its related files, launched the browser interface (firefox.exe), established a successful encrypted connection to the Tor network (tor.exe), and created a file named tor-shopping-list.txt after the session concluded. This timeline confirms that the Tor Browser was fully functional on the VM, used to establish anonymous network connections, and later associated with a local text file creation consistent with user activity following Tor usage.

---

## Response Taken

TOR usage was confirmed on endpoint InternVMWinLou. The device was isolated and the user's direct manager was notified.

---
