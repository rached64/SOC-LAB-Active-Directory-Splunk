# Lab Setup and Prerequisites

## 1. Scope and safety

Use an isolated virtual network and a disposable Active Directory domain. The commands in this repository are for systems you own or are explicitly authorized to test. Do not use production credentials or real privileged accounts.

## 2. Lab variables

Replace all example values with the actual values in your environment.

| Variable | Example | Description |
|---|---|---|
| Domain | `lab.local` | Active Directory DNS domain |
| DC hostname | `dc01.lab.local` | Domain controller FQDN |
| DC IP | `192.168.100.15` | Example only; replace |
| Splunk receiver | `192.168.100.20:9997` | Example only; replace |
| Security index | `windows_server` | Windows Security events |
| Sysmon index | `winlog_vm` | Sysmon Operational events |

On Kali:

```bash
export DC_IP="<DC_IP>"
export DOMAIN="lab.local"
export TEST_USER="test.user"
```

On Windows PowerShell:

```powershell
Import-Module ActiveDirectory
$Domain = "lab.local"
```

## 3. Windows prerequisites

- Windows Server 2022 with Active Directory Domain Services installed.
- A lab domain such as `lab.local`.
- PowerShell with the ActiveDirectory module.
- Windows Security auditing enabled for the event categories used by the selected tests.
- Sysmon installed for UC10.
- Splunk Universal Forwarder installed and configured to forward the Security and Sysmon Operational channels.

Check domain and host information:

```powershell
Get-ComputerInfo | Select-Object CsName, CsDomain, CsPartOfDomain
Get-ADDomain
Get-ADDomainController -Discover
```

## 4. Enable audit policies

Run the following from an elevated PowerShell session on the domain controller. Some subcategory names are localized on non-English Windows installations; check the local policy names if a command fails.

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

Verify:

```powershell
auditpol /get /category:*
```

For Event 4662 DCSync monitoring, configure an appropriate auditing SACL on the domain naming context for the replication rights being monitored. Enabling the Directory Service Access audit subcategory alone does not guarantee that the required 4662 events will be generated.

[INSERT IMAGE HERE: Screenshot of `auditpol /get /category:*` showing the relevant Success and Failure audit subcategories enabled.]

## 5. Splunk receiving and indexes

In Splunk Enterprise:

1. Enable receiving on TCP 9997.
2. Create the `windows_server` index.
3. Create the `winlog_vm` index.
4. Install the Microsoft Windows Add-on compatible with the Splunk version.
5. Confirm the forwarder can connect to the receiver.

[INSERT IMAGE HERE: Splunk Forwarding and Receiving page showing the TCP 9997 receiver enabled.]

[INSERT IMAGE HERE: Splunk indexes configuration showing `windows_server` and `winlog_vm`.]

## 6. Universal Forwarder configuration

Example `inputs.conf`:

```ini
[WinEventLog://Security]
disabled = 0
index = windows_server
start_from = oldest
current_only = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = false
index = winlog_vm
```

Example `outputs.conf`:

```ini
[tcpout]
defaultGroup = splunk_receivers

[tcpout:splunk_receivers]
server = <SPLUNK_SERVER_IP>:9997
```

The `outputs.conf` example is a template. Apply it using the Universal Forwarder's configuration-management method and restart the forwarder after changes.

Restart the Universal Forwarder from an elevated PowerShell prompt:

```powershell
Restart-Service SplunkForwarder
Get-Service SplunkForwarder
```

## 7. Verify collection in Splunk

Security events:

```spl
index=windows_server
| stats count by source sourcetype host
| sort -count
```

Security event IDs:

```spl
index=windows_server
| stats count by EventCode
| sort -count
```

Sysmon events:

```spl
index=winlog_vm
| stats count by EventCode
| sort -count
```

Inspect a raw event and extracted fields:

```spl
index=windows_server earliest=-30m
| head 20
| table _time host source sourcetype EventCode Account_Name
```

If the expected fields are missing, inspect the raw event and use `fieldsummary` before modifying the detection query:

```spl
index=windows_server EventCode=4624
| fieldsummary
```

## 8. Kali prerequisites

Install or verify the tools used by the relevant test:

```bash
python3 --version
impacket-GetUserSPNs -h
impacket-GetNPUsers -h
netexec --help
smbclient --version
```

Depending on the Kali package version, Impacket scripts may be exposed as `GetUserSPNs.py`, `GetNPUsers.py`, or `impacket-GetUserSPNs` / `impacket-GetNPUsers`.

## 9. Time synchronization

Kerberos depends on time synchronization. Check Windows:

```powershell
w32tm /query /status
```

Check Kali:

```bash
timedatectl status
```

Correct time synchronization using the approved lab time source before interpreting Kerberos failures. Do not make arbitrary time changes on production systems.

## 10. Pre-test checklist

- [ ] Lab is isolated and authorized.
- [ ] Test accounts are disposable and documented.
- [ ] No production credentials are used.
- [ ] Required audit policies are enabled.
- [ ] Splunk receiver is listening on TCP 9997.
- [ ] Universal Forwarder service is running.
- [ ] `windows_server` and `winlog_vm` indexes exist.
- [ ] A recent Security event is searchable.
- [ ] Sysmon events are searchable for UC10.
- [ ] System clocks are synchronized.
