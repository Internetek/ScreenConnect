<#
.DESCRIPTION
This script forcefully removes all known traces of ScreenConnect Client (919d3745b4e34229): 
registry keys, uninstall keys, installer codes, service keys, and leftover installation directories.

.VERSION
1.4

.AUTHORS
Caleb Schmetzer - Internetek

.NOTES
This version supports multiple product and compressed codes via environment variables but only targets 
ScreenConnect Client (919d3745b4e34229).
#>

function Remove-ScreenConnectClientInstance {
    Write-Host "- Starting Cleanup for ScreenConnect Client (919d3745b4e34229)"

    # Read product and compressed codes from env vars
    $ProductCodes = @()
    $CompressedCodes = @()

    if ($env:ProblemProductCodes) {
        $ProductCodes = $env:ProblemProductCodes -split ',' | ForEach-Object { $_.Trim() }
        Write-Host "- ProductCodes: $($ProductCodes -join ', ')"
    } else {
        Write-Host "- ERROR: ProblemProductCodes env variable not set. Exiting."
        return
    }

    if ($env:ProblemCompressedCodes) {
        $CompressedCodes = $env:ProblemCompressedCodes -split ',' | ForEach-Object { $_.Trim() }
        Write-Host "- CompressedCodes: $($CompressedCodes -join ', ')"
    } else {
        Write-Host "- ERROR: ProblemCompressedCodes env variable not set. Exiting."
        return
    }

    # Uninstall Keys
    Write-Host "`n- Removing Registry: Uninstall Keys"
    foreach ($ProductCode in $ProductCodes) {
        $UninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
        )
        foreach ($Path in $UninstallPaths) {
            Write-Host "- Processing Key: ${Path}"
            if (Test-Path $Path) {
                try {
                    Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                    Write-Host "- Successfully deleted: ${Path}"
                } catch {
                    Write-Host "- Failed to delete: ${Path}"
                    Write-Host "  Error: $($_.Exception.Message)"
                }
            } else {
                Write-Host "- Key Not Found: ${Path}"
            }
        }
    }

    # Installer Product Keys
    Write-Host "`n- Removing Registry: Installer Product Keys"
    foreach ($Code in $CompressedCodes) {
        $ProductKey = "HKLM:\Software\Classes\Installer\Products\$Code"
        Write-Host "- Processing Key: ${ProductKey}"
        if (Test-Path $ProductKey) {
            try {
                Remove-Item -Path $ProductKey -Recurse -Force -ErrorAction Stop
                Write-Host "- Successfully deleted: ${ProductKey}"
            } catch {
                Write-Host "- Failed to delete: ${ProductKey}"
                Write-Host "  Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "- Key Not Found: ${ProductKey}"
        }
    }

    # Installer UserData Keys
    $UserDataBases = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    )
    Write-Host "`n- Removing Registry: Installer UserData Keys"
    foreach ($BasePath in $UserDataBases) {
        foreach ($Code in $CompressedCodes) {
            $FullPath = "$BasePath\$Code"
            Write-Host "- Processing Key: ${FullPath}"
            if (Test-Path $FullPath) {
                try {
                    Remove-Item -Path $FullPath -Recurse -Force -ErrorAction Stop
                    Write-Host "- Successfully deleted: ${FullPath}"
                } catch {
                    Write-Host "- Failed to delete: ${FullPath}"
                    Write-Host "  Error: $($_.Exception.Message)"
                }
            } else {
                Write-Host "- Key Not Found: ${FullPath}"
            }
        }
    }

    # Specific client ID and service name
    $ClientID = "919d3745b4e34229"
    $TargetServiceName = "ScreenConnect Client ($ClientID)"

    # Stop and delete the ScreenConnect service
    Write-Host "`n- Attempting to Stop and Delete ScreenConnect Service: $TargetServiceName"
    try {
        $Service = Get-Service -Name $TargetServiceName -ErrorAction SilentlyContinue
        if ($Service) {
            if ($Service.Status -ne 'Stopped') {
                Stop-Service -Name $Service.Name -Force -ErrorAction Stop
                Write-Host "- Successfully stopped service: $($Service.Name)"
            }
            sc.exe delete "$($Service.Name)" | Out-Null
            Write-Host "- Successfully deleted service via sc.exe: $($Service.Name)"
        } else {
            Write-Host "- Service not found: $TargetServiceName"
        }
    } catch {
        Write-Host "- Failed to stop or delete service: $TargetServiceName"
        Write-Host "  Error: $($_.Exception.Message)"
    }

    # Remove service registry key
    Write-Host "`n- Removing Registry: Service Key for $TargetServiceName"
    $ServiceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$TargetServiceName"
    if (Test-Path $ServiceKeyPath) {
        try {
            Remove-Item -Path $ServiceKeyPath -Recurse -Force -ErrorAction Stop
            Write-Host "- Successfully deleted service key: $TargetServiceName"
        } catch {
            Write-Host "- Failed to delete service key: $TargetServiceName"
            Write-Host "  Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "- Service registry key not found: $ServiceKeyPath"
    }

    # Filesystem Cleanup – Specific Folder Only
    $SpecificClientPath = "C:\Program Files (x86)\ScreenConnect Client ($ClientID)"
    Write-Host "`n- Checking for conflicting file/folder: $SpecificClientPath"
    if (Test-Path $SpecificClientPath) {
        try {
            Remove-Item -Path $SpecificClientPath -Recurse -Force -ErrorAction Stop
            Write-Host "- Successfully deleted: $SpecificClientPath"
        } catch {
            Write-Host "- Failed to delete: $SpecificClientPath"
            Write-Host "  Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "- No conflicting file/folder found at: $SpecificClientPath"
    }

    Write-Host "`n- Cleanup Completed for ScreenConnect Client (919d3745b4e34229)"
}

Remove-ScreenConnectClientInstance
