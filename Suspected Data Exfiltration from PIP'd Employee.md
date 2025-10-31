We searched through MDE DeviceFileEvents and found regular activity of archiving files and moving to a "backup" folder.
```
DeviceFileEvents
| where DeviceName == "khanglab"
| where FileName endswith ".zip"
```
<img width="1212" alt="image" src="https://github.com/aktran321/threat-hunting-scenario-tor/blob/main/Screenshot%202025-10-30%20at%207.00.19%20PM.png">

Now, we look into DeviceProcessEvents and take the timestamp that the suspicious file was created, and look at what happened 2 minutes before and after.

```
let VName = "khanglab";
let specificTime = datetime("2025-10-22T12:49:04.0059474Z");
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VName
| order by Timestamp desc
| project Timestamp, DeviceId, ProcessCommandLine, ActionType, FileName
```

We find logs indicating that a powershell script (exfiltrateddata.ps1) was downloaded off the internet and then executed.

We then see that `7z.exe` is silently installed and then used to compress the `.csv` file into a `.zip` file.

<img width="1212" alt="image" src="https://github.com/aktran321/threat-hunting-scenario-tor/blob/main/Screenshot%202025-10-30%20at%207.13.18%20PM.png">

I checked for any evidence of data being sent out of the network, but none were found.
```
let VName = "khanglab";
let specificTime = datetime("2025-10-22T12:49:03.9606632Z");
DeviceNetworkEvents
| where Timestamp between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VName
| order by Timestamp desc
```

## MITRE ATT&CK Framework
T1059.001 – PowerShell  
T1105 – Ingress Tool Transfer  
T1564.004 – Hide Artifacts: Hidden Files and Directories  
T1560.001 – Archive Collected Data: Archive via Utility  
T1074 – Data Staged  
T1119 – Automated Collection  
T1036 – Masquerading  
T1218.011 – System Binary Proxy Execution (living-off-the-land)  
T1041 – Exfiltration Over C2 Channel (apply if outbound upload is observed)
