# Scheduled Alert Configuration

Create scheduled alerts only after the corresponding SPL search has been tested manually and returns the expected event fields.

## Recommended alert settings

| Use case | Search window | Schedule (cron) | Trigger condition | Severity |
|---|---|---|---|---|
| UC01 Privileged Group Addition | Last 5 minutes | `*/5 * * * *` | Number of results > 0 | High |
| UC02 Password Spraying | Last 10 minutes | `*/10 * * * *` | Number of results > 0 | Medium |
| UC03 Brute Force | Last 10 minutes | `*/10 * * * *` | Number of results > 0 | High |
| UC04 Kerberoasting | Last 15 minutes | `*/15 * * * *` | Number of results > 0 | High |
| UC05 AS-REP Roasting | Last 15 minutes (proposed) | `*/15 * * * *` (proposed) | Number of results > 0 | High (proposed) |
| UC06 Account creation | Last 10 minutes | `*/10 * * * *` | Number of results > 0 | Medium |
| UC06 Reset followed by login | Last 30 minutes | `*/10 * * * *` | Number of results > 0 | High |
| UC07 Honeytoken | Last 5 minutes | `*/5 * * * *` | Number of results > 0 | Critical |
| UC08 Pass-the-Hash | Last 5 minutes | `*/5 * * * *` | Number of results > 0 | Critical |
| UC09 Golden Ticket / DCSync | Last 15 minutes | `*/15 * * * *` | Number of results > 0 | Critical |
| UC10 LOLBin download | Last 15 minutes | `*/5 * * * *` | Number of results > 0 | Medium |
| ML anomaly | Last 1 hour | `0 * * * *` | Number of results > 0 | Medium; re-evaluate after baseline |

UC05 alert values are proposed and must not be described as validated until the scenario is tested.

## Common Splunk alert workflow

1. Open the saved SPL search.
2. Set the search time range to match the table.
3. Run the search and verify that it returns only the intended detection records.
4. Select **Save As → Alert**.
5. Choose **Scheduled**.
6. Enter the title from the use-case document.
7. Configure the cron schedule.
8. Set the trigger to **Number of Results > 0**.
9. Configure the action to add the result to Triggered Alerts.
10. Set severity and permissions.
11. Save the alert.
12. Run a controlled test and confirm the alert appears in Triggered Alerts.

[INSERT IMAGE HERE: Screenshot of Splunk's Save As Alert form showing a scheduled search, cron schedule, time range, and trigger condition.]

[INSERT IMAGE HERE: Screenshot of Triggered Alerts showing one sanitized test alert with its title, timestamp, and severity.]

## Alert hygiene

- Use a throttle/suppression window where repeated identical events would otherwise create alert floods.
- Keep an allowlist for known service accounts, scanners, and authorized administration activity.
- Record the reason for every exclusion.
- Avoid suppressing high-confidence honeytoken detections without a documented exception.
- Revisit thresholds using real baseline data.
- Do not treat the alert severity as proof that an incident is confirmed.
