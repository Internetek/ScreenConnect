<#
.DESCRIPTION
This script forcefully removes all known traces of ScreenConnect Client (919d3745b4e34229): 
registry keys, uninstall keys, installer codes, service keys, and leftover installation directories.

.VERSION
1.5

.AUTHORS
Caleb Schmetzer - Internetek

.NOTES
This version only targets ScreenConnect Client (919d3745b4e34229)
#>

function Remove-ScreenConnectClientInstance {
    Write-Host "Starting Cleanup for ScreenConnect Client (919d3745b4e34229)"

    # Read product and compressed codes from env vars
    $ProductCodes = @()
    $CompressedCodes = @()

    if ($env:ProblemProductCodes) {
        $ProductCodes = $env:ProblemProductCodes -split ',' | ForEach-Object { $_.Trim() }
        Write-Host "  ProductCodes: $($ProductCodes -join ', ')"
    } else {
        Write-Host "  ProblemProductCodes env variable not set, skipping uninstall key cleanup"
    }

    if ($env:ProblemCompressedCodes) {
        $CompressedCodes = $env:ProblemCompressedCodes -split ',' | ForEach-Object { $_.Trim() }
        Write-Host "  CompressedCodes: $($CompressedCodes -join ', ')"
    } else {
        Write-Host "  ProblemCompressedCodes env variable not set, skipping installer key cleanup"
    }

    # Uninstall Keys
    if ($ProductCodes.Count -gt 0) {
        Write-Host "`nRemoving Registry: Uninstall Keys"
        foreach ($ProductCode in $ProductCodes) {
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
    }

    # Installer Product Keys
    if ($CompressedCodes.Count -gt 0) {
        Write-Host "`nRemoving Registry: Installer Product Keys"
        foreach ($Code in $CompressedCodes) {
            $ProductKey = "HKLM:\Software\Classes\Installer\Products\$Code"
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
            foreach ($Code in $CompressedCodes) {
                $FullPath = "$BasePath\$Code"
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
    }

    $ClientID = "919d3745b4e34229"
    $TargetServiceName = "ScreenConnect Client ($ClientID)"

    # Stop and delete the ScreenConnect service
    Write-Host "`nAttempting to Stop and Delete ScreenConnect Service: '$TargetServiceName'"
    try {
        $Service = Get-Service -Name $TargetServiceName -ErrorAction SilentlyContinue
        if ($Service) {
            if ($Service.Status -ne 'Stopped') {
                Stop-Service -Name $Service.Name -Force -ErrorAction Stop
                Write-Host "  Successfully stopped service: '$($Service.Name)'"
            }
            sc.exe delete "$($Service.Name)" | Out-Null
            Write-Host "  Successfully deleted service: '$($Service.Name)'"
        } else {
            Write-Host "  Service not found: '$TargetServiceName'"
        }
    } catch {
        Write-Host "  Failed to stop or delete service: '$TargetServiceName'"
        Write-Host "  Error: $($_.Exception.Message)"
    }

    # Remove service registry key
    Write-Host "`nRemoving Registry: Service Key for '$TargetServiceName'"
    $ServiceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$TargetServiceName"
    if (Test-Path $ServiceKeyPath) {
        try {
            Remove-Item -Path $ServiceKeyPath -Recurse -Force -ErrorAction Stop
            Write-Host "  Successfully deleted service key: '$TargetServiceName'"
        } catch {
            Write-Host "  Failed to delete service key: '$TargetServiceName'"
            Write-Host "  Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "  Service registry key not found: '$ServiceKeyPath'"
    }

    # Filesystem Cleanup
    $SpecificClientPath = "C:\Program Files (x86)\ScreenConnect Client ($ClientID)"
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

    Write-Host "`nCleanup Completed for ScreenConnect Client (919d3745b4e34229)"
}

Remove-ScreenConnectClientInstance
