<#
.DESCRIPTION
This script performs a comprehensive search for all traces of ScreenConnect installations.
It is designed to continue running even if certain paths or registry keys are inaccessible.

.VERSION
2.0

.AUTHORS
Caleb Schmetzer - Internetek

.NOTES
N/A
#>


function Find-Services {
	try {
        Write-Host "`nChecking Services:"
        $Services = Get-Service | Where-Object { $_.Name -like "*ScreenConnect*" }
        if ($Services) {
            foreach ($Service in $Services) {
                Write-Host "  Service Found: '$($Service.Name)' - Status: $($Service.Status)"
            }
        } else {
            Write-Host "  No ScreenConnect-related services found"
		}
	} catch {
		Write-Host "  Error checking ScreenConnect services: $($_.Exception.Message)"
	}
}

function Find-UninstallKeys {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)][ValidateSet("64-bit","32-bit","Current User")][string]$Scope
	)
	
	Write-Host "`nChecking Registry: Uninstall Keys ($Scope)"
	
	switch ($Scope) {
		"64-bit" {
			$Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
		}
		"32-bit" {
			$Path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
		}
		"Current User" {
			$Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
		}
	}
	
	try {
        $UninstallKeys = Get-ChildItem $Path -ErrorAction Stop |
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
            Write-Host "  No matching entries found in $Scope Uninstall Keys"
        }
    } catch {
        Write-Host "  Error accessing $Scope Uninstall Keys: $($_.Exception.Message)"
    }
}

function Find-InstallerProducts {
    Write-Host "`nChecking Registry: Installer Products:"
    try {
       $InstallerKeys = Get-ChildItem "HKLM:\Software\Classes\Installer\Products" -ErrorAction Stop |
           Where-Object {
                $Props = Get-ItemProperty $_.PSPath -ErrorAction Stop
                ($Props.ProductName -like "*ScreenConnect*")
            }
        if ($InstallerKeys) {
            foreach ($Key in $InstallerKeys) {
                $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
                Write-Host "  Installer Product Found: $($Key.PSChildName) - ProductName: $($Props.ProductName)"
            }
        } else {
            Write-Host "  No matching entries found in Installer Products"
        }
    } catch {
        Write-Host "  Error while accessing Installer Products: $($_.Exception.Message)"
    }
}

function Find-UserDataProducts {
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
                    Write-Host "  No ScreenConnect products found in this UserData path"
                }
            } catch {
                Write-Host "  Error while accessing path '${Path}': $($_.Exception.Message)"
            }
        } else {
            Write-Host "  Path Not Found: '$Path'"
        }
    }
}

function Find-MiscRegistryKeys {
    Write-Host "`nChecking Registry: Other Possible Keys:"
    
	$RegPaths = @(
        "HKLM:\Software\ScreenConnect",
        "HKLM:\Software\WOW6432Node\ScreenConnect",
        "HKCU:\Software\ScreenConnect"
    )
	
    foreach ($Path in $RegPaths) {
        if (Test-Path $Path) {
            Write-Host "  Registry Key Found: '$Path'"
        } else {
            Write-Host "  Key Not Found: '$Path'"
        }
    }
}

function Find-FilesystemFolders {
    Write-Host "`nChecking Filesystem: Common Folders:"
    
	$Folders = @(
        "C:\Program Files\ScreenConnect",
        "C:\Program Files (x86)\ScreenConnect",
        "C:\Program Files (x86)\ScreenConnect Client",
        "C:\ProgramData\ScreenConnect"
    )
	
    foreach ($Folder in $Folders) {
        if (Test-Path $Folder) {
            Write-Host "  Folder Found: '$Folder'"
        } else {
            Write-Host "  Folder Not Found: '$Folder'"
        }
    }
}

function Find-CacheFiles {
    Write-Host "`nChecking Windows Installer Cache:"
    try {
        $InstallerFiles = Get-ChildItem "C:\Windows\Installer" -Filter "*.msi" -ErrorAction Stop |
            Where-Object {
                try {
                    ($_.VersionInfo.ProductName -like "*ScreenConnect*")
                } catch { $false }
            }
        if ($InstallerFiles) {
            foreach ($File in $InstallerFiles) {
				Write-Host "  MSI File Found: '$($File.FullName)'"
			}
        } else {
            Write-Host "  No ScreenConnect-related MSI files found in Installer Cache"
        }
    } catch {
        Write-Host "  Error while accessing Installer Cache: $($_.Exception.Message)"
    }
}

function Find-ScreenConnectTraces {
	Find-Services
	
	$Scopes = @("64-bit", "32-bit", "Current User")
	
	foreach ($Scope in $Scopes) {
		Find-UninstallKeys -Scope $Scope
	}
	
	Find-InstallerProducts
	Find-UserDataProducts
	Find-MiscRegistryKeys
	Find-FilesystemFolders
	Find-CacheFiles
}

Find-ScreenConnectTraces
