# Run from an elevated PowerShell session on the Windows event source.
$Since = (Get-Date).AddMinutes(-30)

$EventIds = @(4624,4625,4662,4720,4724,4728,4732,4756,4768,4769,4771,4776)

foreach ($id in $EventIds) {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = $id
        StartTime = $Since
    } -ErrorAction SilentlyContinue

    [pscustomobject]@{
        EventId = $id
        Count = @($events).Count
    }
}

Write-Host "`nSysmon Event 11 count:"
$sysmon = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 11
    StartTime = $Since
} -ErrorAction SilentlyContinue

@($sysmon).Count
