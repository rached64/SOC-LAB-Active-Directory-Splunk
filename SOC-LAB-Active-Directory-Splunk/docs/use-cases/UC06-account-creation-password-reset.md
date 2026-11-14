# UC06 — Account Creation and Password Reset

| Attribute | Value |
|---|---|
| MITRE ATT&CK | T1136.002 — Create Account: Domain Account; T1098 — Account Manipulation |
| Windows telemetry | 4720 (account created), 4724 (password reset by another account), 4624 (successful logon) |
| Default severity | Medium for unusual creation; High for reset followed by logon |
| Lab status | Validated in the source lab |
| Primary index | `windows_server` |

## 1. Objective

Detect account creation by an actor outside the known administrator allowlist and detect a password reset followed by a rapid successful logon to the same target account.

## 2. How the detection works

The first analytic filters Event 4720 based on the actor. The second correlates Event 4724 with Event 4624 for the same target account within 30 minutes. In this lab, the actor and target can both be represented in multivalue `Account_Name`; `mvindex` is used because `Target_Account_Name` was observed to be empty.

## 3. Prerequisites

- Domain Controller with Security log forwarding.
- Audit `User Account Management` and `Logon` for Success and Failure.
- Disposable test accounts.
- A known allowlist of approved account administrators.

## 4. Required configuration

```powershell
auditpol /get /subcategory:"User Account Management"
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

## 5. Step-by-step simulation

Create a disposable account:

```powershell
New-ADUser `
  -Name "ghost.user" `
  -SamAccountName "ghost.user" `
  -AccountPassword (ConvertTo-SecureString "Temp123!" -AsPlainText -Force) `
  -Enabled $true
```

Reset its password:

```powershell
Set-ADAccountPassword `
  -Identity "ghost.user" `
  -NewPassword (ConvertTo-SecureString "Hacked456!" -AsPlainText -Force) `
  -Reset
```

To test an unusual actor, use a dedicated test administrator and `-Credential`:

```powershell
$cred = Get-Credential
New-ADUser `
  -Name "suspect3.user" `
  -SamAccountName "suspect3.user" `
  -AccountPassword (ConvertTo-SecureString "Temp123!" -AsPlainText -Force) `
  -Enabled $true `
  -Credential $cred
```

Verify the account exists with `Get-ADUser suspect3.user`.

## 6. Verify the Windows event

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4720,4724,4624
    StartTime = (Get-Date).AddMinutes(-30)
} | Select-Object TimeCreated, Id, Message
```

## 7. Splunk detection query

```spl
**A. Account creation by an unexpected actor**

```spl
index="windows_server" source="WinEventLog:Security" EventCode=4720
| eval author=mvindex(Account_Name,0),
       new_account=mvindex(Account_Name,-1)
| where NOT match(author,"(?i)^(administrator|administrateur|svc\.iam)$")
| table _time author new_account host
```

**B. Password reset followed by successful logon**

```spl
index="windows_server" source="WinEventLog:Security"
(EventCode=4724 OR EventCode=4624)
| eval account=lower(mvindex(Account_Name,-1))
| eval action=if(EventCode=4724,"reset","login")
| transaction account
    startswith=eval(action="reset")
    endswith=eval(action="login")
    maxspan=30m
| where eventcount=2
| table _time account duration host
```
```

## 8. Expected results

Expected source-lab observation for account creation:
- Actor: `shadowadmin.temp`.
- New account: `suspect3.user`.
- Event ID: 4720.

Expected reset correlation:
- Event 4724 for the target account.
- Event 4624 for the same target account within 30 minutes.
- One transaction result.

The reset correlation should be checked against the raw event fields to ensure both events refer to the target account, not the actor.

## 9. Scheduled alert

Alert A — Unusual account creation:
- Scheduled; cron `*/10 * * * *`; Last 10 minutes; results > 0; Medium.

Alert B — Password reset followed by logon:
- Scheduled; cron `*/10 * * * *`; Last 30 minutes; results > 0; High.

Both use Add to Triggered Alerts.

## 10. Limitations and false positives

- Replace the hard-coded actor regex with a regularly maintained lookup of approved account administrators.
- Helpdesk password resets are common. The sequence and identity of the target account provide context.
- Confirm `Account_Name` multivalue ordering in your own events.
- A creation followed later by privileged-group addition is a useful correlation opportunity with UC01.

## 11. Cleanup

Disable and remove disposable users after evidence collection. Do not delete any account that is not explicitly a lab test identity.

```powershell
Disable-ADAccount -Identity "ghost.user"
Remove-ADUser -Identity "ghost.user" -Confirm:$false
```

## 12. Screenshot checklist

- [INSERT IMAGE HERE: PowerShell showing creation of `ghost.user` and `suspect3.user`; hide password values.]
- [INSERT IMAGE HERE: Event Viewer Event 4720 with actor and target details.]
- [INSERT IMAGE HERE: Event Viewer Event 4724 and subsequent 4624.]
- [INSERT IMAGE HERE: Splunk account-creation detection result showing actor and new account.]
- [INSERT IMAGE HERE: Splunk transaction result showing reset-to-login duration.]
- [INSERT IMAGE HERE: Triggered Alerts showing the relevant alert and severity.]

## 13. Validation status

Record the actual test date, Windows version, Splunk version, source host, observed Event IDs, number of returned results, and alert status. Do not mark a scenario validated until the complete event-to-alert chain has been demonstrated.
