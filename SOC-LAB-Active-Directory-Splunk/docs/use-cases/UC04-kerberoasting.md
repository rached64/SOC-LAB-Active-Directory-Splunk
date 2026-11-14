# UC04 — Kerberoasting (RC4 Service Ticket)

| Attribute | Value |
|---|---|
| MITRE ATT&CK | T1558.003 — Kerberoasting |
| Windows telemetry | 4769 — Kerberos service ticket requested |
| Default severity | High |
| Lab status | Validated in the source lab |
| Primary index | `windows_server` |

## 1. Objective

Identify service-ticket requests encrypted with RC4-HMAC (`0x17`) for service accounts with SPNs. The ticket material can be subjected to offline password guessing if the service account password is weak.

## 2. How the detection works

The detection filters Event 4769 for `Ticket_Encryption_Type=0x17`, excludes machine accounts and `krbtgt`, and groups by requester and host. In the source lab, the service account `svc.sql` had an SPN and the test requester was `test.user`.

## 3. Prerequisites

- Domain Controller with a service account configured with an SPN.
- Audit `Kerberos Service Ticket Operations` for Success and Failure.
- Kali with Impacket.
- Domain DNS and time synchronization working.

## 4. Required configuration

```powershell
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

## 5. Step-by-step simulation

Create a dedicated service account and SPN on the Domain Controller:

```powershell
New-ADUser `
  -Name "svc.sql" `
  -SamAccountName "svc.sql" `
  -AccountPassword (ConvertTo-SecureString "ServicePass123!" -AsPlainText -Force) `
  -Enabled $true

setspn -A MSSQLSvc/dc01.lab.local:1433 svc.sql
setspn -L svc.sql
```

From Kali, request service tickets in the lab:

```bash
GetUserSPNs.py lab.local/test.user:'<TEST_PASSWORD>' -dc-ip <DC_IP> -request
```

Use the equivalent Impacket command name available in your Kali installation if the `.py` wrapper is not present.

## 6. Verify the Windows event

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4769
    StartTime = (Get-Date).AddMinutes(-15)
} | Select-Object TimeCreated, Id, Message
```

## 7. Splunk detection query

```spl
index="windows_server" source="WinEventLog:Security" EventCode=4769
| where Ticket_Encryption_Type="0x17"
| eval requester=mvindex(Account_Name,-1)
| where NOT like(requester,"%$")
| where Service_Name!="krbtgt"
| stats count
        min(_time) as first_seen
        max(_time) as last_seen
        values(Service_Name) as target_services
        by requester host
| convert ctime(first_seen) ctime(last_seen)
| table requester host first_seen last_seen count target_services
```

## 8. Expected results

Expected source-lab observation:
- Requester: `test.user@LAB.LOCAL`.
- Service: `svc.sql`.
- Encryption type: `0x17` (RC4-HMAC).
- Event ID: 4769.
- A single RC4 ticket for a service account can be meaningful; do not require a high count as the only condition.

## 9. Scheduled alert

- Name: `AD - Kerberoasting (RC4 Ticket)`.
- Type: Scheduled.
- Cron: `*/15 * * * *`.
- Time range: Last 15 minutes.
- Trigger: Number of results > 0.
- Action: Add to Triggered Alerts.
- Severity: High.

## 10. Limitations and false positives

- RC4 can exist for legacy compatibility and is not proof of Kerberoasting by itself.
- The detection is stronger when RC4 is unexpected for the domain and requester.
- Excluding machine accounts reduces noise but may hide some relevant edge cases.
- Validate the exact field name and value representation in your add-on. Some environments render encryption values differently.
- Consider a companion analytic for one requester requesting tickets for many distinct SPNs in a short period.

## 11. Cleanup

Remove the test SPN and disable/remove the disposable service account after capturing evidence:

```powershell
setspn -D MSSQLSvc/dc01.lab.local:1433 svc.sql
Disable-ADAccount -Identity svc.sql
Remove-ADUser -Identity svc.sql -Confirm:$false
```

## 12. Screenshot checklist

### Splunk detection results :
 ![Splunk detection results showing requester, service, and `0x17`](../../screenshots/UC4.PNG)

