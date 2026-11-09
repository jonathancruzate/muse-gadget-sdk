#Requires -Version 5.1
<#
.SYNOPSIS
    Register, query, or unregister the post-reboot continuation scheduled task
    for the Muse Gadget PC bridge.

.DESCRIPTION
    When Primary Mode applies a rename that requires a reboot, this helper registers
    a Scheduled Task (default name: MuseGadgetPcBridgeContinue) triggered at user
    logon so the PC automatically opens the pairing window, watches for pairing.json,
    and restores the original computer/Bluetooth name.

    Supports -WhatIf / -Confirm via SupportsShouldProcess.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Register', 'Unregister', 'Status')]
    [string]$Action = 'Status',

    [Parameter(Mandatory = $false)]
    [string]$TaskName = 'MuseGadgetPcBridgeContinue',

    [Parameter(Mandatory = $false)]
    [string]$PythonExe = '',

    [Parameter(Mandatory = $false)]
    [string]$ScriptPath = '',

    [Parameter(Mandatory = $false)]
    [string]$StateDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Action -eq 'Status') {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $out = [ordered]@{
        action     = 'Status'
        task_name  = $TaskName
        registered = [bool]($null -ne $task)
        state      = if ($null -ne $task) { [string]$task.State } else { 'Absent' }
    }
    $out | ConvertTo-Json -Compress
    exit 0
}

if ($Action -eq 'Register') {
    if ([string]::IsNullOrWhiteSpace($PythonExe) -or [string]::IsNullOrWhiteSpace($ScriptPath)) {
        throw "-PythonExe and -ScriptPath are required when -Action Register is specified."
    }
    $argList = "`"$ScriptPath`" continue --execute"
    if (-not [string]::IsNullOrWhiteSpace($StateDir)) {
        $argList += " --state-dir `"$StateDir`""
    }
    if ($PSCmdlet.ShouldProcess("ScheduledTask '$TaskName' -> $PythonExe $argList", "Register-ScheduledTask")) {
        $taskAction = New-ScheduledTaskAction -Execute $PythonExe -Argument $argList
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Settings $settings -Force | Out-Null
    }
    exit 0
}

if ($Action -eq 'Unregister') {
    if ($PSCmdlet.ShouldProcess("ScheduledTask '$TaskName'", "Unregister-ScheduledTask")) {
        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    }
    exit 0
}
