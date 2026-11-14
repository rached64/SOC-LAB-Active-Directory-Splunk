# Validation and Evidence Guide

## Evidence standard

For every use case, capture evidence in this order:

1. **Simulation:** terminal or PowerShell window showing the exact test command. Hide passwords, tokens, hashes, and sensitive host details.
2. **Windows telemetry:** Event Viewer event details showing the relevant Event ID and timestamp.
3. **Splunk raw event:** the original event in the correct index.
4. **Splunk detection:** the final SPL query and its result table.
5. **Alert:** the triggered alert, if the alert is configured.
6. **Cleanup:** confirmation that temporary users, group memberships, SPNs, and test settings have been removed or restored.

## Screenshot naming convention

Use names such as:

```text
UC01-01-test-account-created.png
UC01-02-event-4728-event-viewer.png
UC01-03-splunk-detection-results.png
UC01-04-triggered-alert.png
```

## Sanitization checklist

Before committing evidence to GitHub:

- [ ] Replace public and private IPs if disclosure is not intended.
- [ ] Mask usernames that identify real people.
- [ ] Remove passwords and password lists.
- [ ] Mask NTLM hashes, AES keys, Kerberos tickets, and ticket caches.
- [ ] Remove domain SIDs if they should not be public.
- [ ] Remove email addresses, machine names, and organization names where necessary.
- [ ] Confirm that terminal history does not expose secrets.
- [ ] Confirm that screenshots do not show unrelated browser tabs or internal systems.

## Evidence placeholders

Each use-case page contains exact `[INSERT IMAGE HERE: ...]` placeholders. Store the corresponding images in `screenshots/` and update the Markdown path, for example:

```markdown
![UC01 Event 4728 in Event Viewer](../../screenshots/UC01-02-event-4728-event-viewer.png)
```

Do not leave a screenshot placeholder in the final public version if the evidence has not been captured; either add the image or label the evidence as pending.
