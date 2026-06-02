# Splunk Universal Forwarder Setup

## Environment
- Splunk Indexer: `172.25.1.102:9997`
- Domain: `marvel.local`
- Index: `windows_lab`

---

## inputs.conf

Location: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
index = windows_lab
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1
renderXml = 0

[WinEventLog://System]
index = windows_lab
disabled = 0

[WinEventLog://Application]
index = windows_lab
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = windows_lab
disabled = 0
renderXml = 1
```

---

## outputs.conf

Location: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 172.25.1.102:9997

[tcpout-server://172.25.1.102:9997]
```

---

## Restart Forwarder

```powershell
Restart-Service SplunkForwarder
```

## Verify Connection

On Splunk indexer, run:
```spl
index=windows_lab | stats count by host
```

Both `WIN-SERVER` and `WIN10` should appear.
