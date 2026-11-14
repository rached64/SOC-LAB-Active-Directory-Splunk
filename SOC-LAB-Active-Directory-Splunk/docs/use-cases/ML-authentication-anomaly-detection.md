# Machine Learning Module — Authentication Failure Anomaly Detection with Splunk MLTK

| Attribute | Value |
|---|---|
| Technique context | T1110 — Brute Force (complementary behavioral detection) |
| Data | Windows Security Event 4625 |
| Algorithm | Splunk MLTK `DensityFunction` |
| Model | `modele_echecs_dc` |
| Status | Fit/apply workflow validated; representative baseline still in progress |

## 1. Objective

Use statistical modeling to learn the normal distribution of authentication failures per host and flag unusual hourly volumes. This complements fixed-threshold detections such as Password Spraying and Brute Force.

## 2. How it works

The training search groups Event 4625 records into one-hour buckets by host and fits a `DensityFunction` model. The apply search scores new hourly counts and returns records whose anomaly indicator is 1.

The source lab detected a peak of 15,659 failures as an outlier. However, the first model had only five data points, including deliberate attack-test spikes. This is insufficient for a reliable production baseline.

## 3. Prerequisites

- Splunk Machine Learning Toolkit installed.
- Python for Scientific Computing app installed at a compatible version.
- Windows Security events indexed in `windows_server`.
- A representative period of normal authentication activity.
- Permissions to create and use the model in the Splunk app context.

## 4. Verify MLTK capability

The source project used this minimal fit test:

```spl
| makeresults count=20
| streamstats count as x
| eval y=x*2+random()%10
| fit LinearRegression y from x
```

## 5. Train the model

```spl
index="windows_server" source="WinEventLog:Security" EventCode=4625
| bin _time span=1h
| stats count as echecs by _time host
| fit DensityFunction echecs by "host" into app:modele_echecs_dc
```

The `app:` prefix is a literal model-sharing scope in the source configuration; it is not a placeholder to replace with an app name.

## 6. Apply the model

```spl
index="windows_server" source="WinEventLog:Security" EventCode=4625
| bin _time span=1h
| stats count as echecs by _time host
| apply modele_echecs_dc threshold=0.01
| rename "IsOutlier(echecs)" as est_anomalie
| where est_anomalie=1
| table _time host echecs est_anomalie
```

The source lab noted that `IsOutlier(echecs)` must be quoted because the field name contains parentheses.

## 7. Expected results

The recorded source-lab sample:

| Hour | Failed logons | Outlier indicator |
|---|---:|---:|
| 19 Oct 2026 15:00 | 7 | 0 |
| 20 Oct 2026 11:00 | 992 | 0 |
| 20 Oct 2026 15:00 | 15,659 | 1 |
| 22 Oct 2026 10:00 | 3 | 0 |
| 22 Oct 2026 11:00 | 8 | 0 |

The model isolated the 15,659-failure peak. The baseline was still immature.

## 8. Build a normal baseline

The source lab proposed simulating ordinary authentication activity from Kali every 20–40 minutes during business hours, with occasional mistyped passwords. Use only disposable lab accounts and keep the generator at a low rate.

Example baseline generator:

```bash
#!/usr/bin/env bash
DC_IP="<DC_IP>"
USER="test.user"
PASS='<TEST_PASSWORD>'

while true; do
    HOUR=$(date +%H)
    if [ "$HOUR" -ge 8 ] && [ "$HOUR" -le 19 ]; then
        if [ $((RANDOM % 10)) -eq 0 ]; then
            netexec smb "$DC_IP" -u "$USER" -p '<INCORRECT_TEST_PASSWORD>' 2>/dev/null
        fi
        netexec smb "$DC_IP" -u "$USER" -p "$PASS" 2>/dev/null
    fi
    sleep $(( (RANDOM % 1200) + 1200 ))
done
```

Do not use real user accounts or credentials. Stop the script with Ctrl+C when enough test data has been collected. The source documentation proposed collecting two to three days of normal-like data, then training a new model such as `modele_echecs_dc_v2`.

## 9. Scheduled alert

- Name: `AD - Authentication Failure Anomaly (MLTK)`.
- Type: Scheduled.
- Cron: `0 * * * *`.
- Time range: Last 1 hour.
- Trigger: Number of results > 0.
- Action: Add to Triggered Alerts.
- Severity: Medium, to be reviewed after baseline maturity.

The source alert was created but was to be reactivated after re-training.

## 10. Limitations

- A small number of points does not represent normal behavior.
- Attack simulations included in the training period can distort the distribution.
- One host provides limited context.
- Consider modeling per user, per host, or across multiple authentication features only after enough representative data exists.
- Compare ML results with fixed-threshold detections before changing operational alerting.

## 11. Screenshot checklist

- [INSERT IMAGE HERE: Splunk MLTK app showing the DensityFunction model training search.]
- [INSERT IMAGE HERE: Model training search completing successfully and saving `modele_echecs_dc`.]
- [INSERT IMAGE HERE: Apply search showing `IsOutlier(echecs)` or `est_anomalie`.]
- [INSERT IMAGE HERE: Table or visualization highlighting the 15,659 failure anomaly.]
- [INSERT IMAGE HERE: Baseline collection script running in Kali with credentials hidden.]
- [INSERT IMAGE HERE: Scheduled ML alert configuration, clearly marked inactive until the baseline is re-trained.]
