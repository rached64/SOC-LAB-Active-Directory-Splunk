# UC03 — Brute Force: Failures Followed by Success

| Attribute | Value |
|---|---|
| MITRE ATT&CK | T1110.001 — Password Guessing / Brute Force |
| Windows telemetry | 4625 (failure) and 4624 (success) |
| Default severity | High |
| Lab status | Validated in the source lab |
| Primary index | `windows_server` |

## 1. Objective

Detect repeated failed authentication attempts against one account followed by a successful logon from the same source. A successful logon after a burst of failures raises the potential impact.

## 2. How the detection works

The search normalizes the account name, derives a source address, buckets events into 10-minute windows, and counts failed and successful logons. It alerts when failures exceed five and at least one success is present in the same account/source/time bucket.

## 3. Prerequisites

- Security log collection from the Domain Controller.
- Audit `Logon` for Success and Failure.
- Kali with NetExec or smbclient.
- Dedicated test account and known valid test password.

## 4. Required configuration

```powershell
auditpol /get /subcategory:"Logon"
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

## 5. Step-by-step simulation

Kali example using SMB authentication attempts:

```bash
for i in $(seq 1 8); do
  smbclient -L "//<DC_IP>/" -U "test.user%wrongpass$i" 2>/dev/null
done
```

Then make one successful authentication using the lab account's valid password:

```bash
smbclient -L "//<DC_IP>/" -U 'test.user%<VALID_TEST_PASSWORD>'
```

Use an isolated test account. Do not run password guessing against real users or services.

## 6. Verify the Windows event

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624,4625
    StartTime = (Get-Date).AddMinutes(-15)
} | Select-Object TimeCreated, Id, Message
```

## 7. Splunk detection query

```spl
index="windows_server" source="WinEventLog:Security"
(EventCode=4625 OR EventCode=4624)
| eval account=lower(mvindex(Account_Name,-1))
| eval source=if(
    Source_Network_Address="0.0.0.0" OR Source_Network_Address="-",
    coalesce(Workstation_Name,host),
    Source_Network_Address
)
| eval result=if(EventCode=4625,"failure","success")
| where account!="-" AND NOT like(account,"%$")
| bin _time span=10m
| stats count(eval(result="failure")) as failures
        count(eval(result="success")) as successes
        by _time account source
| where failures > 5 AND successes > 0
| table _time account source failures successes
```

## 8. Expected results

Expected lab result:
- Account: `test.user`.
- Failed attempts: 8.
- Successful attempts: 1.
- Events: 4625 followed by 4624.
- Source: the Kali test host.
- Severity: High.

## 9. Scheduled alert

- Name: `AD - Brute Force (Failures Followed by Success)`.
- Type: Scheduled.
- Cron: `*/10 * * * *`.
- Time range: Last 10 minutes.
- Trigger: Number of results > 0.
- Action: Add to Triggered Alerts.
- Severity: High.

## 10. Limitations and false positives

- A user may mistype a password several times before succeeding. Validate with the user and source context.
- The query requires the success and failures to land in the same 10-minute bucket. A more advanced implementation can correlate a rolling time window.
- Confirm that the successful event is attributable to the same source and target account.
- The source lab found that SMB/NetExec can provide a useful `Source_Network_Address` for this scenario.

## 11. Cleanup

No account state changes are required. Remove any temporary password-list file from Kali.

## 12. Screenshot checklist

### Splunk table showing `test.user`, the source, eight failures, and one succes 
 ![Splunk table showing `test.user`, the source, eight failures, and one succes ](../../screenshots/UC3.PNG)
