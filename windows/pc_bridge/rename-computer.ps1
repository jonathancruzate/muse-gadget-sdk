#Requires -Version 5.1
<#
.SYNOPSIS
    Query or set the Windows physical DNS hostname (and NetBIOS computer name)
    for Muse Gadget PC pairing (Primary Mode Path 1B).

.DESCRIPTION
    PowerShell's built-in Rename-Computer cmdlet rejects names longer than 15 characters
    because of the legacy NetBIOS limit, whereas MuseGadgetXXXXXX is 16 characters.
    This helper uses Win32 SetComputerNameExW(ComputerNamePhysicalDnsHostname = 5, name),
    which Microsoft documents as setting the full physical DNS hostname (16 chars) while
    truncating the NetBIOS name to the first 15 characters (or restoring the original
    name on restore).

    Never reboots automatically; reboot is always an explicit owner step.
    Supports -WhatIf / -Confirm via SupportsShouldProcess.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Query', 'Set', 'Restore')]
    [string]$Action = 'Query',

    [Parameter(Mandatory = $false)]
    [string]$NewName = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$code = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Win32ComputerName {
    public enum COMPUTER_NAME_FORMAT {
        ComputerNameNetBIOS = 0,
        ComputerNameDnsHostname = 1,
        ComputerNameDnsDomain = 2,
        ComputerNameDnsFullyQualified = 3,
        ComputerNamePhysicalNetBIOS = 4,
        ComputerNamePhysicalDnsHostname = 5,
        ComputerNamePhysicalDnsDomain = 6,
        ComputerNamePhysicalDnsFullyQualified = 7
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetComputerNameExW(
        COMPUTER_NAME_FORMAT NameType,
        StringBuilder lpBuffer,
        ref uint lpnSize
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool SetComputerNameExW(
        COMPUTER_NAME_FORMAT NameType,
        string lpBuffer
    );

    public static string ReadName(COMPUTER_NAME_FORMAT fmt) {
        uint size = 260;
        StringBuilder sb = new StringBuilder((int)size);
        if (!GetComputerNameExW(fmt, sb, ref size)) {
            return "";
        }
        return sb.ToString();
    }
}
"@

if (-not ('Win32ComputerName' -as [type])) {
    Add-Type -TypeDefinition $code -Language CSharp
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$activeNetbios = [Win32ComputerName]::ReadName([Win32ComputerName+COMPUTER_NAME_FORMAT]::ComputerNameNetBIOS)
$activeDns     = [Win32ComputerName]::ReadName([Win32ComputerName+COMPUTER_NAME_FORMAT]::ComputerNameDnsHostname)
$physNetbios   = [Win32ComputerName]::ReadName([Win32ComputerName+COMPUTER_NAME_FORMAT]::ComputerNamePhysicalNetBIOS)
$physDns       = [Win32ComputerName]::ReadName([Win32ComputerName+COMPUTER_NAME_FORMAT]::ComputerNamePhysicalDnsHostname)

if ($Action -eq 'Query') {
    $out = [ordered]@{
        action           = 'Query'
        is_admin         = (Test-IsAdmin)
        netbios_name     = $activeNetbios
        dns_hostname     = $activeDns
        physical_netbios = $physNetbios
        physical_dns     = $physDns
    }
    $out | ConvertTo-Json -Compress
    exit 0
}

if ([string]::IsNullOrWhiteSpace($NewName)) {
    throw "-NewName is required for Action '$Action'."
}

$predictedNetbios = if ($NewName.Length -gt 15) { $NewName.Substring(0, 15) } else { $NewName }
$targetDesc = "PhysicalDnsHostname='$NewName' (NetBIOS='$predictedNetbios')"

if ($PSCmdlet.ShouldProcess($targetDesc, "$Action computer name via SetComputerNameExW")) {
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges are required to call SetComputerNameExW."
    }
    $ok = [Win32ComputerName]::SetComputerNameExW(
        [Win32ComputerName+COMPUTER_NAME_FORMAT]::ComputerNamePhysicalDnsHostname,
        $NewName
    )
    if (-not $ok) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "SetComputerNameExW failed with Win32 error $err."
    }
}
exit 0
