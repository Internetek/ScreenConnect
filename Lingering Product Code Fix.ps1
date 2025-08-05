<#
.DESCRIPTION
This script forcefully removes all known traces of ScreenConnect: registry keys,
uninstall keys, installer product codes, service keys, and leftover installation directories

.VERSION
1.1

.AUTHORS
Caleb Schmetzer - Internetek

.NOTES
Meant for use with LingeringInstallationsSearch
You may have to use it and add product/compressed codes from there if this script
doesn't cover the codes for the versions you are trying to clean up
#>

function Remove-ScreenConnectTraces {
    Write-Host "- Starting ScreenConnect Cleanup"

    $KnownProductCodes = @(
        "{DAFDC526-E09C-461A-9F8D-D6B9A3C5BF54}",
        "{F5708C2F-B665-C91F-18BE-06B8AE43E565}",
	"{9EEBA193-E8DA-0453-8638-3DDC04F4B8BE}"
    )

    $CompressedCodes = @(
        "625CDFADC90EA164F9D86D9B3A5CFB45",  # {DAFDC526-E09C-461A-9F8D-D6B9A3C5BF54}
        "F2C8075F566BF19C81EB608BEA345E56",  # {F5708C2F-B665-C91F-18BE-06B8AE43E565}
	"391ABEE9AD8E35406883D3CD404F8BEB"   # {9EEBA193-E8DA-0453-8638-3DDC04F4B8BE}
    )

    # Uninstall Keys
    Write-Host "`n- Removing Registry: Uninstall Keys"
    foreach ($ProductCode in $KnownProductCodes) {
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

    # Installer UserData Product Keys
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

    # Other Registry Keys
    $ExtraRegPaths = @(
        "HKCU:\Software\ScreenConnect",
        "HKLM:\Software\ScreenConnect",
        "HKLM:\Software\WOW6432Node\ScreenConnect"
    )
    Write-Host "`n- Removing Registry: ScreenConnect Application Keys"
    foreach ($Path in $ExtraRegPaths) {
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

	# Stop and delete all ScreenConnect services
	Write-Host "`n- Attempting to Stop and Delete ScreenConnect Services"
	$Services = Get-Service | Where-Object { $_.Name -like "ScreenConnect Client (*)" }
	
	if ($Services) {
	    foreach ($Service in $Services) {
	        try {
	            if ($Service.Status -ne 'Stopped') {
	                Stop-Service -Name $Service.Name -Force -ErrorAction Stop
	                Write-Host "- Successfully stopped service: $($Service.Name)"
	            }
	        } catch {
	            Write-Host "- Failed to stop service: $($Service.Name)"
	            Write-Host "  Error: $($_.Exception.Message)"
	        }
	
	        try {
	            sc.exe delete "$($Service.Name)" | Out-Null
	            Write-Host "- Successfully deleted service via sc.exe: $($Service.Name)"
	        } catch {
	            Write-Host "- Failed to delete service via sc.exe: $($Service.Name)"
	            Write-Host "  Error: $($_.Exception.Message)"
	        }
	    }
	} else {
	    Write-Host "- No ScreenConnect services found to stop/delete"
	}
	
	# Remove all ScreenConnect service registry keys
	Write-Host "`n- Removing Registry: ScreenConnect Service Keys"
	$ServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services"
	$ServiceKeys = Get-ChildItem -Path $ServicePath | Where-Object {
	    $_.PSChildName -like "ScreenConnect Client (*)"
	}
	
     if ($ServiceKeys) {
	    foreach ($Key in $ServiceKeys) {
	        Write-Host "- Found Service Key: $($Key.PSPath)"
	        try {
	            Remove-Item -Path $Key.PSPath -Recurse -Force -ErrorAction Stop
	            Write-Host "- Successfully deleted service key: $($Key.PSChildName)"
	        } catch {
	            Write-Host "- Failed to delete service key: $($Key.PSChildName)"
	            Write-Host "  Error: $($_.Exception.Message)"
	        }
	    }
	} else {
	    Write-Host "- No ScreenConnect service registry keys found"
	}


    # Filesystem Cleanup
    $InstallDirs = @(
        "C:\Program Files\ScreenConnect",
        "C:\Program Files (x86)\ScreenConnect",
        "C:\Program Files (x86)\ScreenConnect Client",
        "C:\ProgramData\ScreenConnect"
    )
    Write-Host "`n- Cleaning Filesystem: ScreenConnect Install Folders"
    foreach ($Folder in $InstallDirs) {
        Write-Host "- Processing Folder: ${Folder}"
        if (Test-Path $Folder) {
            try {
                Remove-Item -Path $Folder -Recurse -Force -ErrorAction Stop
                Write-Host "- Successfully deleted: ${Folder}"
            } catch {
                Write-Host "- Failed to delete: ${Folder}"
                Write-Host "  Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "- Folder Not Found: ${Folder}"
        }
    }
	
    $ClientDirs = @(
        "C:\Program Files\ScreenConnect Client*",
        "C:\Program Files (x86)\ScreenConnect Client*"
    )
    Write-Host "`n- Cleaning Filesystem: Client Wildcard Folders"
    foreach ($Wildcard in $ClientDirs) {
        $Dirs = Get-ChildItem -Path $Wildcard -Directory -ErrorAction SilentlyContinue
        foreach ($Dir in $Dirs) {
            Write-Host "- Deleting Directory: $($Dir.FullName)"
            try {
                Remove-Item -Path $Dir.FullName -Recurse -Force -ErrorAction Stop
                Write-Host "- Successfully deleted: $($Dir.FullName)"
            } catch {
                Write-Host "- Failed to delete: $($Dir.FullName)"
                Write-Host "  Error: $($_.Exception.Message)"
            }
        }
    }
	
    Write-Host "`n- ScreenConnect Cleanup Completed"
}
Remove-ScreenConnectTraces
