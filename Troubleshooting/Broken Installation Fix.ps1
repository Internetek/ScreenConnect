<#
.DESCRIPTION
This script removes all traces of a broken ScreenConnect installation: 
registry keys, uninstall keys, installer codes, service keys, and leftover installation directories.
It is designed to continue running even if certain paths or registry keys are inaccessible. 

.VERSION
2.0

.AUTHORS
Caleb Schmetzer - Internetek

.NOTES
This version is no longer reliant on the ScreenConnect Installations Search script as it 
finds problem codes dynamically based on the target client. 
#>

if ([string]::IsNullOrWhiteSpace($env:TargetClientThumbprint)) {
    Write-Host " TargetClientThumbprint variable is not set in Datto. Please enter a client to cleanup"
    Write-Host "Exiting with error"
    exit 1
}


# Checks if script is running with administrative privileges
function Test-IsElevated {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}



$TargetClient = "ScreenConnect Client ($env:TargetClientThumbprint)"
$script:ProblemProductCodes = @()
$script:ProblemCompressedCodes = @()

function Find-ProblemCompressedCodes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TargetClient
    )
    
    Write-Host "`nChecking Registry: Installer Products:"
    
    try {
        $InstallerKeys = Get-ChildItem "HKLM:\Software\Classes\Installer\Products" -ErrorAction Stop |
            Where-Object {
                try {
                    $Props = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    $Props.ProductName -like "*$TargetClient*"
                } catch {
                    $false
                }
            }
        if ($InstallerKeys) {
            foreach ($Key in $InstallerKeys) {
                try {
                    $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
                    Write-Host "  Installer Product Found: $($Key.PSChildName) - ProductName: $($Props.ProductName)"
                    $FoundCode = $Key.PSChildName
                    $script:ProblemCompressedCodes += $FoundCode
                } catch {
                    Write-Host "  Error reading key $($Key.PSPath): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "  No matching entries found in Installer Products"
        }
    } catch {
        Write-Host "  Error while accessing Installer Products: $($_.Exception.Message)"
    }
}

function Find-ProblemProductCodes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][ValidateSet("64-bit","32-bit","Current User")][string]$Scope,
        [Parameter(Mandatory=$true)][string]$TargetClient
    )
    
    Write-Host "`nChecking Registry: Uninstall Keys ($Scope)"
    
    switch ($Scope) {
        "64-bit"     { $Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
        "32-bit"     { $Path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" }
        "Current User" { $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    }
    
    try {
        $UninstallKeys = Get-ChildItem $Path -ErrorAction Stop |
            Where-Object {
                try {
                    $Props = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    $Props.DisplayName -like "*$TargetClient*"
                } catch {
                    $false
                }
            }
        if ($UninstallKeys) {
            foreach ($Key in $UninstallKeys) {
                try {
                    $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
                    Write-Host "  Uninstall Key Found: $($Key.PSChildName) - DisplayName: $($Props.DisplayName)"
                    $FoundCode = $Key.PSChildName
                    $script:ProblemProductCodes += $FoundCode
                } catch {
                    Write-Host "  Error reading key $($Key.PSPath): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "  No matching entries found in $Scope Uninstall Keys"
        }
    } catch {
        Write-Host "  Error accessing $Scope Uninstall Keys: $($_.Exception.Message)"
    }
}

function Remove-ScreenConnectClientInstance {
    Write-Host "Starting Cleanup for $TargetClient"

    # Uninstall Keys
    if ($script:ProblemProductCodes.Count -gt 0) {
        Write-Host "`nRemoving Registry: Uninstall Keys"
        foreach ($ProductCode in $script:ProblemProductCodes) {
            $UninstallPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
            )
            foreach ($Path in $UninstallPaths) {
                Write-Host "  Processing Key: '${Path}'"
                if (Test-Path $Path) {
                    try {
                        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                        Write-Host "  Successfully deleted: '${Path}'"
                    } catch {
                        Write-Host "  Failed to delete: '${Path}'"
                        Write-Host "  Error: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "  Key Not Found: '${Path}'"
                }
            }
        }
    } else {
        Write-Host "`nNo uninstall product codes found to remove."
    }

    # Installer Product Keys
    if ($script:ProblemCompressedCodes.Count -gt 0) {
        Write-Host "`nRemoving Registry: Installer Product Keys"
        foreach ($CompressedCode in $script:ProblemCompressedCodes) {
            $ProductKey = "HKLM:\Software\Classes\Installer\Products\$CompressedCode"
            Write-Host "  Processing Key: '${ProductKey}'"
            if (Test-Path $ProductKey) {
                try {
                    Remove-Item -Path $ProductKey -Recurse -Force -ErrorAction Stop
                    Write-Host "  Successfully deleted: '${ProductKey}'"
                } catch {
                    Write-Host "  Failed to delete: '${ProductKey}'"
                    Write-Host "  Error: $($_.Exception.Message)"
                }
            } else {
                Write-Host "  Key Not Found: '${ProductKey}'"
            }
        }

        # Installer UserData Keys
        $UserDataBases = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
        )
        Write-Host "`nRemoving Registry: Installer UserData Keys"
        foreach ($BasePath in $UserDataBases) {
            foreach ($CompressedCode in $script:ProblemCompressedCodes) {
                $FullPath = "$BasePath\$CompressedCode"
                Write-Host "  Processing Key: '${FullPath}'"
                if (Test-Path $FullPath) {
                    try {
                        Remove-Item -Path $FullPath -Recurse -Force -ErrorAction Stop
                        Write-Host "  Successfully deleted: '${FullPath}'"
                    } catch {
                        Write-Host "  Failed to delete: '${FullPath}'"
                        Write-Host "  Error: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "  Key Not Found: '${FullPath}'"
                }
            }
        }
    } else {
        Write-Host "`nNo compressed installer product codes found to remove."
    }

    # Stop and delete the ScreenConnect service
    Write-Host "`nAttempting to Stop and Delete ScreenConnect Service: '$TargetClient'"
    try {
        # Try exact, then fallback to wildcards that still confirm equality
        $Service = Get-Service -Name $TargetClient -ErrorAction SilentlyContinue
        if (-not $Service) {
            $Service = Get-Service -Name 'ScreenConnect Client*' -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -eq $TargetClient }
        }

        if ($Service) {
            if ($Service.Status -ne 'Stopped') {
                Stop-Service -Name $Service.Name -Force -ErrorAction Stop
                Write-Host "  Successfully stopped service: '$($Service.Name)'"
            }
            sc.exe delete "$($Service.Name)" | Out-Null
            Write-Host "  Successfully deleted service: '$($Service.Name)'"
        } else {
            Write-Host "  Service not found: '$TargetClient'"
        }
    } catch {
        Write-Host "  Failed to stop or delete service: '$TargetClient'"
        Write-Host "  Error: $($_.Exception.Message)"
    }

    # Remove service registry key
    Write-Host "`nRemoving Registry: Service Key for '$TargetClient'"
    $ServiceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$TargetClient"
    if (Test-Path $ServiceKeyPath) {
        try {
            Remove-Item -Path $ServiceKeyPath -Recurse -Force -ErrorAction Stop
            Write-Host "  Successfully deleted service key: '$TargetClient'"
        } catch {
            Write-Host "  Failed to delete service key: '$TargetClient'"
            Write-Host "  Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "  Service registry key not found: '$ServiceKeyPath'"
    }

    # Filesystem Cleanup
    $SpecificClientPath = "C:\Program Files (x86)\ScreenConnect Client ($env:TargetClientThumbprint)"
    Write-Host "`nChecking for folder: $SpecificClientPath"
    if (Test-Path $SpecificClientPath) {
        try {
            Remove-Item -Path $SpecificClientPath -Recurse -Force -ErrorAction Stop
            Write-Host "  Successfully deleted: '$SpecificClientPath'"
        } catch {
            Write-Host "  Failed to delete: '$SpecificClientPath'"
            Write-Host "  Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "  No folder found at: '$SpecificClientPath'"
    }

    Write-Host "`nCleanup Completed for $TargetClient"
}


if (-not (Test-IsElevated)) {
	Write-Host "  This script must be run as an administrator, exiting"
	exit 1
}

$Scopes = @("64-bit", "32-bit", "Current User")

foreach ($Scope in $Scopes) {
    Find-ProblemProductCodes -Scope $Scope -TargetClient $TargetClient
}

Find-ProblemCompressedCodes -TargetClient $TargetClient

Start-Sleep -Seconds 3

Remove-ScreenConnectClientInstance
