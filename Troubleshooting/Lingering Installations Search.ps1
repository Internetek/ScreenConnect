<#
.DESCRIPTION
This script searches for performs a comprehensive search for all traces of ScreenConnect installations.
This is a tool meant to be used for when there are issues with the install/uninstall, such as lingering
product codes.

.VERSION
1.0

.AUTHORS
Caleb Schmetzer - Internetek

.NOTES
Known product codes can be added as needed. Each is associated with a compressed code in the registry, which this script will help find. 
#>


function Find-ScreenConnectTraces {
    Write-Host "- Starting ScreenConnect Lingering Installations Search"

    $KnownProductCodes = @(
        "{DAFDC526-E09C-461A-9F8D-D6B9A3C5BF54}",
        "{BF3098D4-63EA-EE16-1FAA-019CADEC9565}",
        "{F5708C2F-B665-C91F-18BE-06B8AE43E565}",
        "{D88B4423-4E69-D034-A875-73EB884B0F94}"
    )

    # Services
    Write-Host "`n- Checking Services:"
    $Services = Get-Service | Where-Object { $_.Name -like "*ScreenConnect*" }
    if ($Services) {
        foreach ($Service in $Services) {
            Write-Host "- Service Found: $($Service.Name) - Status: $($Service.Status)"
        }
    } else {
        Write-Host "- No ScreenConnect-related services found."
    }

    # Registry - Uninstall Keys (64-bit)
    Write-Host "`n- Checking Registry: Uninstall Keys (64-bit):"
    $UninstallKeys = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Where-Object {
            $Props = Get-ItemProperty $_.PSPath
            ($Props.DisplayName -like "*ScreenConnect*") -or ($KnownProductCodes -contains $_.PSChildName)
        }
    if ($UninstallKeys) {
        foreach ($Key in $UninstallKeys) {
            $Props = Get-ItemProperty $Key.PSPath
            Write-Host "- Uninstall Key Found: $($Key.PSChildName) - DisplayName: $($Props.DisplayName)"
        }
    } else {
        Write-Host "- No matching entries found in 64-bit Uninstall Keys."
    }

    # Registry - Uninstall Keys (32-bit)
    Write-Host "`n- Checking Registry: Uninstall Keys (32-bit):"
    $UninstallKeys32 = Get-ChildItem "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Where-Object {
            $Props = Get-ItemProperty $_.PSPath
            ($Props.DisplayName -like "*ScreenConnect*") -or ($KnownProductCodes -contains $_.PSChildName)
        }
    if ($UninstallKeys32) {
        foreach ($Key in $UninstallKeys32) {
            $Props = Get-ItemProperty $Key.PSPath
            Write-Host "- Uninstall Key Found: $($Key.PSChildName) - DisplayName: $($Props.DisplayName)"
        }
    } else {
        Write-Host "- No matching entries found in 32-bit Uninstall Keys."
    }

    # Registry - Uninstall Keys (Current User - HKCU)
    Write-Host "`n- Checking Registry: Uninstall Keys (Current User - HKCU):"
    $UninstallKeysUser = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        Where-Object {
            $Props = Get-ItemProperty $_.PSPath
            ($Props.DisplayName -like "*ScreenConnect*")
        }
    if ($UninstallKeysUser) {
        foreach ($Key in $UninstallKeysUser) {
            $Props = Get-ItemProperty $Key.PSPath
            Write-Host "- User Uninstall Key Found: $($Key.PSChildName) - DisplayName: $($Props.DisplayName)"
        }
    } else {
        Write-Host "- No matching entries found in Current User Uninstall Keys."
    }

    # Registry - Installer Products (64-bit)
    Write-Host "`n- Checking Registry: Installer Products (64-bit):"
    $InstallerKeys = Get-ChildItem "HKLM:\Software\Classes\Installer\Products" -ErrorAction SilentlyContinue |
        Where-Object {
            $Props = Get-ItemProperty $_.PSPath
            ($Props.ProductName -like "*ScreenConnect*") -or ($KnownProductCodes -contains $_.PSChildName)
        }
    if ($InstallerKeys) {
        foreach ($Key in $InstallerKeys) {
            $Props = Get-ItemProperty $Key.PSPath
            Write-Host "- Installer Product Found: $($Key.PSChildName) - ProductName: $($Props.ProductName)"
        }
    } else {
        Write-Host "- No matching entries found in Installer Products."
    }

    # Registry - Installer UserData Products (64-bit & 32-bit)
    $UserDataPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    )
    foreach ($Path in $UserDataPaths) {
        Write-Host "`n- Checking Installer UserData Products at ${Path}:"
        if (Test-Path $Path) {
            $UserDataKeys = Get-ChildItem $Path -ErrorAction SilentlyContinue |
                Where-Object {
                    try {
                        $Pn = (Get-ItemProperty $_.PSPath).ProductName
                        $Pn -like "*ScreenConnect*"
                    } catch { $false }
                }
            if ($UserDataKeys) {
                foreach ($Key in $UserDataKeys) {
                    $Pn = (Get-ItemProperty $Key.PSPath).ProductName
                    Write-Host "- UserData Product Found: $($Key.PSChildName) - ProductName: $Pn"
                }
            } else {
                Write-Host "- No ScreenConnect products found in this UserData path."
            }
        } else {
            Write-Host "- Path Not Found: $Path"
        }
    }

    # Registry - Other ScreenConnect-related Keys
    Write-Host "`n- Checking Registry: Other Possible Keys:"
    $RegPaths = @(
        "HKLM:\Software\ScreenConnect",
        "HKLM:\Software\WOW6432Node\ScreenConnect",
        "HKCU:\Software\ScreenConnect"
    )
    foreach ($Path in $RegPaths) {
        if (Test-Path $Path) {
            Write-Host "- Registry Key Found: $Path"
        } else {
            Write-Host "- Key Not Found: $Path"
        }
    }

    # Filesystem - Common Install Locations
    Write-Host "`n- Checking Filesystem: Common Folders:"
    $Folders = @(
        "C:\Program Files\ScreenConnect",
        "C:\Program Files (x86)\ScreenConnect",
        "C:\Program Files (x86)\ScreenConnect Client",
        "C:\ProgramData\ScreenConnect"
    )
    foreach ($Folder in $Folders) {
        if (Test-Path $Folder) {
            Write-Host "- Folder Found: $Folder"
        } else {
            Write-Host "- Folder Not Found: $Folder"
        }
    }

    # Windows Installer Cache - ScreenConnect MSI Files
    Write-Host "`n- Checking Windows Installer Cache:"
    $InstallerFiles = Get-ChildItem "C:\Windows\Installer" -Filter "*.msi" -ErrorAction SilentlyContinue |
        Where-Object {
            try {
                ($_.VersionInfo.ProductName -like "*ScreenConnect*") -or ($_.Name -match "($($KnownProductCodes -join '|'))")
            } catch { $false }
        }
    if ($InstallerFiles) {
        foreach ($File in $InstallerFiles) {
            Write-Host "- MSI File Found: $($File.FullName)"
        }
    } else {
        Write-Host "- No ScreenConnect-related MSI files found in Installer Cache."
    }

    Write-Host "`n- Search Completed"
}

Find-ScreenConnectTraces
