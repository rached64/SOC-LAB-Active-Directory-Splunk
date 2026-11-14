# Run from an elevated PowerShell session on the lab domain controller.
# Subcategory display names may be localized on non-English Windows installations.

$Subcategories = @(
    "Logon",
    "Credential Validation",
    "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "Security Group Management",
    "User Account Management",
    "Directory Service Access"
)

foreach ($subcategory in $Subcategories) {
    Write-Host "Enabling Success and Failure auditing for: $subcategory"
    auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable
}

Write-Host "`nCurrent audit policy:"
auditpol /get /category:*
