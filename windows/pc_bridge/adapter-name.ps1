#Requires -Version 5.1
<#
.SYNOPSIS
    Query, override, or restore the Windows Bluetooth radio Local Name in the registry
    without renaming the OS computer (Primary Mode Path 1A for Muse Gadget PC pairing).

.DESCRIPTION
    Windows' Bluetooth port driver (bthport.sys) reads per-radio parameters from:
      HKLM:\SYSTEM\CurrentControlSet\Enum\<InstanceId>\Device Parameters
    Setting the 'Local Name' value (REG_BINARY, null-terminated UTF-8 bytes) and cycling
    the Bluetooth radio PnP device asks bthport.sys to advertise the full 16-character
    MuseGadgetXXXXXX name without hitting the 15-character NetBIOS computer name limit
    or rebooting the PC.

    Supports -WhatIf / -Confirm via SupportsShouldProcess.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Query', 'Set', 'Restore')]
    [string]$Action = 'Query',

    [Parameter(Mandatory = $false)]
    [string]$NewName = '',

    [Parameter(Mandatory = $false)]
    [string]$InstanceId = '',

    [Parameter(Mandatory = $false)]
    [string]$OriginalLocalNameHex = '',

    [Parameter(Mandatory = $false)]
    [switch]$NoBounce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-BluetoothRadioDevice {
    param([string]$RequestedInstanceId)
    $btDevices = @(Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue)
    if ($RequestedInstanceId) {
        $match = $btDevices | Where-Object { $_.InstanceId -eq $RequestedInstanceId } | Select-Object -First 1
        if ($match) { return $match }
    }
    # Prefer hardware USB/PCI radio enumerators (Realtek, Intel, CSR, Generic Bluetooth Adapter)
    $radio = $btDevices | Where-Object {
        $_.Status -eq 'OK' -and
        $_.InstanceId -match '^(USB|PCI|USB\\VID_)' -and
        $_.FriendlyName -notmatch 'Enumerator|RFCOMM|Service|Avrcp|Tdi'
    } | Select-Object -First 1
    if (-not $radio) {
        $radio = $btDevices | Where-Object { $_.InstanceId -match '^(USB|PCI)' } | Select-Object -First 1
    }
    return $radio
}

function Get-DeviceParametersRegPath {
    param([string]$DevInstanceId)
    return "HKLM:\SYSTEM\CurrentControlSet\Enum\$DevInstanceId\Device Parameters"
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Count -eq 0) { return '' }
    return ($Bytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function ConvertFrom-HexString {
    param([string]$Hex)
    if ([string]::IsNullOrWhiteSpace($Hex)) { return [byte[]]@() }
    $clean = $Hex.Trim()
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return $bytes
}

$radio = Find-BluetoothRadioDevice -RequestedInstanceId $InstanceId
$resolvedInstanceId = if ($radio) { [string]$radio.InstanceId } else { $InstanceId }
$friendlyName = if ($radio) { [string]$radio.FriendlyName } else { '' }
$regPath = if ($resolvedInstanceId) { Get-DeviceParametersRegPath -DevInstanceId $resolvedInstanceId } else { '' }

$existingBytes = $null
if ($regPath -and (Test-Path -LiteralPath $regPath)) {
    $prop = Get-ItemProperty -LiteralPath $regPath -Name 'Local Name' -ErrorAction SilentlyContinue
    if ($null -ne $prop -and $null -ne $prop.'Local Name') {
        $existingBytes = [byte[]]$prop.'Local Name'
    }
}
$existingHex = if ($null -ne $existingBytes) { ConvertTo-HexString -Bytes $existingBytes } else { '' }
$existingText = if ($null -ne $existingBytes) {
    ([Text.Encoding]::UTF8.GetString($existingBytes)).TrimEnd([char]0)
} else { '' }

if ($Action -eq 'Query') {
    $out = [ordered]@{
        action                   = 'Query'
        is_admin                 = (Test-IsAdmin)
        instance_id              = $resolvedInstanceId
        friendly_name            = $friendlyName
        registry_path            = $regPath
        registry_path_exists     = [bool]($regPath -and (Test-Path -LiteralPath $regPath))
        local_name_hex           = $existingHex
        local_name_text          = $existingText
    }
    $out | ConvertTo-Json -Compress
    exit 0
}

if (-not $resolvedInstanceId -or -not $regPath) {
    throw "No Bluetooth radio adapter instance found to $Action."
}

if ($Action -eq 'Set') {
    if ([string]::IsNullOrWhiteSpace($NewName)) {
        throw "-NewName is required when -Action Set is specified."
    }
    $utf8Bytes = [Text.Encoding]::UTF8.GetBytes($NewName)
    if ($utf8Bytes.Length -ge 248) {
        throw "NewName exceeds the 248-byte Bluetooth Local Name limit ($($utf8Bytes.Length) bytes)."
    }
    # Null-terminated UTF-8 REG_BINARY as expected by bthport.sys
    $payload = New-Object byte[] ($utf8Bytes.Length + 1)
    [Array]::Copy($utf8Bytes, 0, $payload, 0, $utf8Bytes.Length)
    $payload[$utf8Bytes.Length] = 0

    if ($PSCmdlet.ShouldProcess("$regPath [Local Name = '$NewName']", "Set REG_BINARY Local Name and bounce radio")) {
        if (-not (Test-IsAdmin)) {
            throw "Administrator privileges are required to write $regPath."
        }
        New-ItemProperty -LiteralPath $regPath -Name 'Local Name' -PropertyType Binary -Value $payload -Force | Out-Null
        if (-not $NoBounce -and $radio) {
            Disable-PnpDevice -InstanceId $resolvedInstanceId -Confirm:$false
            Start-Sleep -Seconds 2
            Enable-PnpDevice -InstanceId $resolvedInstanceId -Confirm:$false
            Start-Sleep -Seconds 2
        }
    }
    exit 0
}

if ($Action -eq 'Restore') {
    if ($PSCmdlet.ShouldProcess("$regPath [Local Name]", "Restore original Local Name and bounce radio")) {
        if (-not (Test-IsAdmin)) {
            throw "Administrator privileges are required to restore $regPath."
        }
        if ([string]::IsNullOrWhiteSpace($OriginalLocalNameHex)) {
            if (Test-Path -LiteralPath $regPath) {
                Remove-ItemProperty -LiteralPath $regPath -Name 'Local Name' -ErrorAction SilentlyContinue
            }
        } else {
            $origBytes = ConvertFrom-HexString -Hex $OriginalLocalNameHex
            New-ItemProperty -LiteralPath $regPath -Name 'Local Name' -PropertyType Binary -Value $origBytes -Force | Out-Null
        }
        if (-not $NoBounce -and $radio) {
            Disable-PnpDevice -InstanceId $resolvedInstanceId -Confirm:$false
            Start-Sleep -Seconds 2
            Enable-PnpDevice -InstanceId $resolvedInstanceId -Confirm:$false
            Start-Sleep -Seconds 2
        }
    }
    exit 0
}
