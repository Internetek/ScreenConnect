<#
.DESCRIPTION
This script performs a comprehensive search for all traces of ScreenConnect installations.
It is designed to continue running even if certain paths or registry keys are inaccessible.

.VERSION
1.1

.AUTHORS
Caleb Schmetzer - Internetek
#>

function Find-ScreenConnectTraces {
    Write-Host "Starting ScreenConnect Lingering Installations Search"

    try {
        # Services
        Write-Host "`nChecking Services:"
        $Services = Get-Service | Where-Object { $_.Name -like "*ScreenConnect*" }
        if ($Services) {
            foreach ($Service in $Services) {
                Write-Host "  Service Found: $($Service.Name) - Status: $($Service.Status)"
            }
        } else {
            Write-Host "  No ScreenConnect-related services found."
        }

        # Registry Uninstall Keys (64-bit)
        Write-Host "`nChecking Registry: Uninstall Keys (64-bit):"
        try {
            $UninstallKeys = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction Stop |
                Where-Object {
                    $Props = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    $Props.DisplayName -like "*ScreenConnect*"
                }
            if ($UninstallKeys) {
                foreach ($Key in $UninstallKeys) {
                    $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
                    Write-Host "  Uninstall Key Found: $($Key.PSChildName) - DisplayName: $($Props.DisplayName)"
                }
            } else {
                Write-Host "  No matching entries found in 64-bit Uninstall Keys."
            }
        } catch {
            Write-Host "  Failed to access 64-bit Uninstall Keys. Error: $($_.Exception.Message)"
        }

        # Registry Uninstall Keys (32-bit)
        Write-Host "`nChecking Registry: Uninstall Keys (32-bit):"
        try {
            $UninstallKeys32 = Get-ChildItem "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction Stop |
                Where-Object {
                    $Props = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    ($Props.DisplayName -like "*ScreenConnect*") -or ($KnownProductCodes -contains $_.PSChildName)
                }
            if ($UninstallKeys32) {
                foreach ($Key in $UninstallKeys32) {
                    $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
                    Write-Host "  Uninstall Key Found: $($Key.PSChildName) - DisplayName: $($Props.DisplayName)"
                }
            } else {
                Write-Host "  No matching entries found in 32-bit Uninstall Keys."
            }
        } catch {
            Write-Host "  Failed to access 32-bit Uninstall Keys. Error: $($_.Exception.Message)"
        }

        # Registry Uninstall Keys (HKCU)
        Write-Host "`nChecking Registry: Uninstall Keys (Current User - HKCU):"
        try {
            $UninstallKeysUser = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction Stop |
                Where-Object {
                    $Props = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    $Props.DisplayName -like "*ScreenConnect*"
                }
            if ($UninstallKeysUser) {
                foreach ($Key in $UninstallKeysUser) {
                    $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
                    Write-Host "  User Uninstall Key Found: $($Key.PSChildName) - DisplayName: $($Props.DisplayName)"
                }
            } else {
                Write-Host "  No matching entries found in Current User Uninstall Keys."
            }
        } catch {
            Write-Host "  Error while accessing Current User Uninstall Keys: $($_.Exception.Message)"
        }

        # Registry Installer Products
        Write-Host "`nChecking Registry: Installer Products:"
        try {
            $InstallerKeys = Get-ChildItem "HKLM:\Software\Classes\Installer\Products" -ErrorAction Stop |
                Where-Object {
                    $Props = Get-ItemProperty $_.PSPath -ErrorAction Stop
                    ($Props.ProductName -like "*ScreenConnect*") -or ($KnownProductCodes -contains $_.PSChildName)
                }
            if ($InstallerKeys) {
                foreach ($Key in $InstallerKeys) {
                    $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
                    Write-Host "  Installer Product Found: $($Key.PSChildName) - ProductName: $($Props.ProductName)"
                }
            } else {
                Write-Host "  No matching entries found in Installer Products."
            }
        } catch {
            Write-Host "  Error while accessing Installer Products: $($_.Exception.Message)"
        }

        # Registry UserData Products
        $UserDataPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
        )
        foreach ($Path in $UserDataPaths) {
            Write-Host "`nChecking Installer UserData Products at ${Path}:"
            if (Test-Path $Path) {
                try {
                    $UserDataKeys = Get-ChildItem $Path -ErrorAction Stop |
                        Where-Object {
                            try {
                                $Pn = (Get-ItemProperty $_.PSPath -ErrorAction Stop).ProductName
                                $Pn -like "*ScreenConnect*"
                            } catch { $false }
                        }
                    if ($UserDataKeys) {
                        foreach ($Key in $UserDataKeys) {
                            $Pn = (Get-ItemProperty $Key.PSPath -ErrorAction Stop).ProductName
                            Write-Host "  UserData Product Found: $($Key.PSChildName) - ProductName: $Pn"
                        }
                    } else {
                        Write-Host "  No ScreenConnect products found in this UserData path."
                    }
                } catch {
                    Write-Host "  Error while accessing path ${Path}: $($_.Exception.Message)"
                }
            } else {
                Write-Host "  Path Not Found: $Path"
            }
        }

        # Other Registry Keys
        Write-Host "`nChecking Registry: Other Possible Keys:"
        $RegPaths = @(
            "HKLM:\Software\ScreenConnect",
            "HKLM:\Software\WOW6432Node\ScreenConnect",
            "HKCU:\Software\ScreenConnect"
        )
        foreach ($Path in $RegPaths) {
            if (Test-Path $Path) {
                Write-Host "  Registry Key Found: $Path"
            } else {
                Write-Host "  Key Not Found: $Path"
            }
        }

        # Filesystem Folders
        Write-Host "`nChecking Filesystem: Common Folders:"
        $Folders = @(
            "C:\Program Files\ScreenConnect",
            "C:\Program Files (x86)\ScreenConnect",
            "C:\Program Files (x86)\ScreenConnect Client",
            "C:\ProgramData\ScreenConnect"
        )
        foreach ($Folder in $Folders) {
            if (Test-Path $Folder) {
                Write-Host "  Folder Found: $Folder"
            } else {
                Write-Host "  Folder Not Found: $Folder"
            }
        }

        # MSI Cache Files
        Write-Host "`nChecking Windows Installer Cache:"
        try {
            $InstallerFiles = Get-ChildItem "C:\Windows\Installer" -Filter "*.msi" -ErrorAction Stop |
                Where-Object {
                    try {
                        ($_.VersionInfo.ProductName -like "*ScreenConnect*") -or ($_.Name -match "($($KnownProductCodes -join '|'))")
                    } catch { $false }
                }
            if ($InstallerFiles) {
                foreach ($File in $InstallerFiles) {
                    Write-Host "  MSI File Found: $($File.FullName)"
                }
            } else {
                Write-Host "  No ScreenConnect-related MSI files found in Installer Cache."
            }
        } catch {
            Write-Host "  Error while accessing Installer Cache: $($_.Exception.Message)"
        }

    } catch {
        Write-Host "  An unexpected error occurred during the search: $($_.Exception.Message)"
    }

    Write-Host "`nSearch Completed"
}

# Call safely, ensure script doesn't terminate if this fails
try {
    Find-ScreenConnectTraces
} catch {
    Write-Host "  Script failed to execute properly: $($_.Exception.Message)"
}
