<#
.DESCRIPTION
This script installs ScreenConnect on endpoints. 
It's been hacked together from multiple scripts and our own code to make the most reliable installer possible and get around issues with ThreatLocker blocking the randomized MSI produced by ScreenConnect.
There is loads of output and checks because it makes it easier for me to diagnose issues in the script when working with remote endpoints.

.VERSION
5.0

.AUTHORS
John Miller - Internetek
Caleb Schmetzer - Internetek

.RESOURCES
https://www.reddit.com/r/ConnectWiseControl/comments/vwut4k/silently_deploy_the_connectwise_control_agent/
https://www.ninjaone.com/script-hub/automate-connectwise-screenconnect-deployment-with-powershell/

.OPTIONS
Action: Tells the script which action we're taking

.VARIABLES
CWScreenConnectThumbprint: Set at Global level in DRMM. Identifies the ScreenConnect instance and verifies the installer.
CWScreenConnectBaseUrl: Set at Global level in DRMM. URL of our ScreenConnect instance.
CWScreenConnectInstallerUrl: URL of the ScreenConnect installer. Set at the Client level.
CWScreenConnectusrUDF: UDF where we'll put the ScreenConnect link. Set at the Global level.
#>
Write-Host "Starting script"
# === SETTING AND ENUMERATING VARIABLES === #
Write-Host "Version 5.0" # Reported to make sure DRMM is using the current version
Write-Host "Variables received from DRMM"
Write-Host "  Thumbprint: $env:CWScreenConnectThumbprint"
Write-Host "  Base URL: $env:CWScreenConnectBaseUrl"
Write-Host "  Installer URL: $env:CWScreenConnectURL"
Write-Host "  UDF: $env:CWScreenConnectusrUDF"
Write-Host "  Action: $env:ScriptAction"
Write-Host "  Script: $PSCommandPath" # So we can find the working dir for diagnostics
$ProductName = "ScreenConnect" # Name of the software we're working with
$InstallerFile = "Internetek.ClientSetup.msi" # Generic name so we can call it in the script
$InstallerLogFile = "InstallLog.txt" # Dumps the install log so we can see what went wrong
$DownloadUrl = $env:CWScreenConnectURL # Changing specific to generic for Download-Installer function
$IsOverrideEnabled = $env:OverrideChecks -eq "True" # Converts override environ variable into a boolean
$InstallBasePath = "C:\Program Files (x86)\ScreenConnect Client ($env:CWScreenConnectThumbprint)" # Base directory path for ScreenConnect install
$ServiceName = "ScreenConnect Client ($env:CWScreenConnectThumbprint)" # Service name for ScreenConnect instance

# === FUNCTIONS === #
Write-Host "Setting functions"
# Checks if we're working with elevated credentials
function Test-IsElevated {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Checks if ScreenConnect has been installed 
function Test-IsScreenConnectInstalled {
    try {
        $ServiceKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction Stop | Where-Object { $_.Name -match "ScreenConnect Client \(" }
        return $ServiceKeys.Count -gt 0
    } catch {
        throw "Failed to access registry to check for ScreenConnect: $($_.Exception.Message)"
    }
}

# Stops ScreenConnect service and reports result
function Stop-SCService {
    try {
        $SCServices = Get-Service | Where-Object { $_.Name -match "^ScreenConnect Client \(.+\)$" }
        if ($SCServices) {
            $SCServices | Stop-Service -Force -ErrorAction Stop
            return $true
        } else {
            Write-Host "  No ScreenConnect Client services found."
            return $false
        }
    } catch {
        Write-Host "  Error stopping ScreenConnect services: $($_.Exception.Message)"
        return $false
    }
}

function Stop-SCProcesses {
    # Get all processes that start with "ScreenConnect"
    $Processes = Get-Process | Where-Object { $_.Name -like "ScreenConnect*" }
    if (-not $Processes) {
        Write-Host "  No ScreenConnect processes found."
        return $true
    }

    $AllStopped = $true
    foreach ($Process in $Processes) {
        try {
            Write-Host "  Stopping process: $($Process.Name) (ID: $($Process.Id))"
            Stop-Process -Id $Process.Id -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 200
            if (Get-Process -Id $Process.Id -ErrorAction SilentlyContinue) {
                Write-Host "  Process still running after Stop-Process."
                $AllStopped = $false
            }
        } catch {
            Write-Host "  Couldn't stop process: $($_.Exception.Message)"
            $AllStopped = $false
        }
    }
    return $AllStopped
}


# Creates a JoinLink in DRMM under the provided UDF
function Create-JoinLink {
    $null = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:CWScreenConnectThumbprint)" -Name ImagePath).ImagePath -Match '(&s=[a-f0-9\-]*)'
    $Guid = $Matches[0] -replace '&s='
    $ApiLaunchUrl= "$($env:CWScreenConnectBaseUrl)" + "Host#Access///" + $Guid + "/Join"
    New-ItemProperty -Path "HKLM:\Software\CentraStage" -Name "Custom$env:CWScreenConnectusrUDF" -PropertyType String -Value $ApiLaunchUrl -force | out-null
    Write-Host "  UDF written to UDF#$env:CWScreenConnectusrUDF."
}

# Sets the TLS version based on what the endpoint supports
function Set-TlsVersion {
	$SupportedTlsVersions = [enum]::GetValues([System.Net.SecurityProtocolType])
    if ($SupportedTlsVersions -contains [System.Net.SecurityProtocolType]::Tls13) {
        Write-Host "  Using TLS1.3"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
		return [System.Net.SecurityProtocolType]::Tls13
    } elseif ($SupportedTlsVersions -contains [System.Net.SecurityProtocolType]::Tls12) {
        Write-Host "  Using TLS1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		return [System.Net.SecurityProtocolType]::Tls12
    } else {
        Write-Warning "  TLS 1.2 or TLS 1.3 isn't supported on this system. This download may fail!"
		return $null
    }
}

# Downloader
function Download-Installer {
    Write-Host "  Downloading install file"
	$PrimaryTls = Set-TlsVersion
	
    # Download the file
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerFile
        if (-not (Test-Path -Path $InstallerFile)) {
            throw "  File download failed"
        }
    } catch {
        Write-Error "  Download failed: $_"
        if ($PrimaryTls -eq [System.Net.SecurityProtocolType]::Tls13) {
            Write-Output "  Retrying with TLS1.2"
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerFile
                if (-not (Test-Path -Path $InstallerFile)) {
                    throw "  File download failed on second attempt"
                }
            } catch {
                Write-Error "  Second attempt failed: $_"
                exit 1
            }
        } else {
            exit 1
        }
    }
    Write-Output "  $InstallerFile downloaded"
}

# Install action
function Install-ScreenConnect {
    Write-Host "Starting install"
    # Calling download function
    Download-Installer
    # Installing file
	if ($IsOverrideEnabled) {
		Write-Host "  Override called, using MSI Transform"
		#$Arguments = "/i $InstallerFile TRANSFORMS=""InstallOverride.mst"" /qn /norestart /l ""$InstallerLogFile"""
		$Arguments = "/i $InstallerFile /qn /norestart /l ""$InstallerLogFile"""
	} else {
		$Arguments = "/i $InstallerFile /qn /norestart /l ""$InstallerLogFile"""
	}
    $Process = (Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -Passthru)
    switch ($Process.ExitCode) {
        0 { Write-Host "  Install appears successful" }
        3010 { Write-Host "  Install appears successful. Reboot required to complete installation" }
        1641 { Write-Host "  Install appears successful. Installer has initiated a reboot" }
        default {
            Write-Host "  Exit code does not indicate success, dumping log:"
            Write-Host "  +++++++++++++++++++++++++++++++++"
            Get-Content $InstallerLogFile -ErrorAction SilentlyContinue | Select-Object -Last 50 | Write-Host
            Write-Host "  +++++++++++++++++++++++++++++++++"
        }
    }
    # Delete install file so we don't clutter up the drive
    Write-Host "Cleaning up"
    try {
        rm .\$InstallerFile -ErrorAction Stop
        Write-Host "  File deleted"
    } catch {
        Write-Host "  Failed to delete file" 
        Write-Host " " $_.Exception.Message
    }
    if ($Process.ExitCode -ne 0) {
        Write-Host "Install appears to have failed, exiting script"
        exit 1
    }
    # Make sure it started
    Write-Host "Checking install success"
    # Get service status
    Write-Host "  Getting Service status"
    $StartService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($StartService.length -gt 0) {
        if ($StartService.Status -eq 'Running') {
            Write-Host "  Service exists and is started"
        } else {
            Write-Host "  Service exists but is not started, attempting to start service"
            Start-Service $ServiceName
        }
        Write-Host "Creating link in UDF"
        # Writing link to DRRM UDF
        Create-JoinLink
    } else {
        Write-Host "  Service doesn't exist, exiting script with error"
        exit 1
    }
}

# Uninstall action
function Uninstall-ScreenConnect {
    Write-Host "Starting uninstall"
    Write-Host "  Stopping service"
	
	# Stopping service and processes, supposed to help with uninstall
	if (Stop-SCService) {
		Write-Host "  Service has stopped"
	} else { 
		Write-Host "  Service is still running"
	}
	
	if (Stop-SCProcesses) {
		Write-Host "  Processes have stopped"
	} else {
		Write-Host "  One or more processes failed to stop"
	}
	
    # Attempt uninstall using Method #1
    Write-Host "  Attempting registry string uninstall"
	
	$UninstallCompleted = $false
	
	 $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
	
	foreach ($Path in $UninstallPaths) {
        Get-ChildItem $Path -ErrorAction SilentlyContinue | ForEach-Object {
            $App = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($App.DisplayName -like "*ScreenConnect Client*" -and $App.UninstallString) {
                Write-Host "  Found: $($App.DisplayName)"
                Write-Host "  Uninstalling using the registry string: $($App.UninstallString)"
                $UninstallString = $App.UninstallString.Trim()
    
                $Parts = $UninstallString -split '\s+', 2
                $ExePath = $Parts[0]
                $Arguments = if ($Parts.Count -ge 2) { $Parts[1] } else { "" }
    
                # Resolve executable path from path if necessary
                $Command = Get-Command $ExePath -ErrorAction SilentlyContinue
		if ($Command) {
		    $ExePath = $Command.Source
		} else {
		    Write-Host "  Error: Executable $ExePath not found in path. Skipping."
		    continue
		}
    
                # Add silent flags
                if ($ExePath -match 'msiexec.exe') {
                    if ($Arguments -notmatch "/quiet|/qn|/s|/silent") {
                        $Arguments += " /qn /norestart"
                    }
                } else {
                    if ($Arguments -notmatch "/quiet|/qn|/s|/silent") {
                        $Arguments += " /quiet"
                    }
                }
    
                Write-Host "  Executing uninstall: $ExePath $Arguments"
                try {
                    Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -ErrorAction Stop
                    Write-Host "  Registry uninstall command executed"
                } catch {
                    Write-Host "  Registry uninstall failed: $($_.Exception.Message)"
                }
    
                Start-Sleep -Seconds 5
    
                if (-not (Test-IsScreenConnectInstalled)) {
                    Write-Host "  Uninstall was successful using registry string method."
                    $UninstallCompleted = $true
                    break
                } else {
                    Write-Host "  ScreenConnect still installed, trying next path."
                }
            }
        }
        
		if ($UninstallCompleted) { break }
    }
	
    
	# Attempt uninstall using Method #2
	if (-not $UninstallCompleted) {
		Write-Host "  Attemping Get-Package uninstall"
        try {
            $Packages = Get-Package | Where-Object { $_.Name -like "ScreenConnect Client*" }
            foreach ($Package in $Packages) {
                Write-Host "  Attempting to uninstall package: $($Package.Name)"
                $Package | Uninstall-Package -ErrorAction Stop | Out-Null
                Write-Host "    Successfully uninstalled $($Package.Name)"
            }
        } catch {
            Write-Host "  Get-Package uninstall failed: $($_.Exception.Message)"
        }
       
		Start-Sleep -Seconds 5
		
        if (-not (Test-IsScreenConnectInstalled)) {
            Write-Host "  Uninstall was successful using the Get-Package method."
            $UninstallCompleted = $true
        } else {
            Write-Host "  ScreenConnect still installed after Get-Package uninstall."
        }
    }
	
	if (-not($UninstallCompleted) -and $IsOverrideEnabled) {
		Write-Host "  Override enabled, forcing uninstall."
		
		# Attempt uninstall using Method #3
		Write-Host "  Attempting CIM-based uninstall"
		try {
			$ScreenConnectProducts = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like "*ScreenConnect Client*" }
			foreach ($App in $ScreenConnectProducts) {
				Write-Host "  Uninstalling using CIM method: $($App.Name)"
				$CIMResult = Invoke-CimMethod -InputObject $App -MethodName Uninstall
				Write-Host "  CIM uninstall method returned: $($CIMResult.ReturnValue)"
			}
		} catch {
			Write-Host "  CIM-based uninstall failed: $($_.Exception.Message)"
		}
		
		Start-Sleep -Seconds 5
	
        if (-not (Test-IsScreenConnectInstalled)) {
            Write-Host "  Uninstall was successful using the CIM-based method."
            $UninstallCompleted = $true
        } else {
            Write-Host "  ScreenConnect still installed after CIM-based uninstall."
        }
		
		# Attempting uninstall using Method #4
		
		if (-not $UninstallCompleted) {
		Write-Host "  Attempting WMI-based uninstall"
		$WmiProducts = @()
			try {
				$WmiProducts = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*ScreenConnect Client*" }
				foreach ($App in $WmiProducts) {
					Write-Host "  Found installed product via WMI: $($App.Name) - $($App.IdentifyingNumber)"
					$ProductCode = $App.IdentifyingNumber
					Write-Host "  Attempting uninstall via msiexec for product code: $ProductCode"
					Start-Process "msiexec.exe" -ArgumentList "/x $ProductCode /qn" -Wait -ErrorAction Stop
				}
			} catch {
				Write-Host "  WMI query or uninstall using msiexec failed: $($_.Exception.Message)"
			}
			
			Start-Sleep -Seconds 5
		
			if (-not (Test-IsScreenConnectInstalled)) {
				Write-Host "  Uninstall was successful using the WMI-based method."
				$UninstallCompleted = $true
			} else {
				Write-Host " ScreenConnect still installed after WMI-based install."
			}
		}
		
		# Last resort manual uninstallation 
		if (-not $UninstallCompleted) {
			Write-Host "  Attempting to manually remove ScreenConnect"
			
			# Uninstall known product codes
			$KnownProductCodes = @(
				"{DAFDC526-E09C-461A-9F8D-D6B9A3C5BF54}",
				"{BF3098D4-63EA-EE16-1FAA-019CADEC9565}"
			)
			
			foreach ($ProductCode in $KnownProductCodes) {
				Write-Host "  Attempting to uninstall using msiexec for known product code: $ProductCode"
				try {
					Start-Process "msiexec.exe" -ArgumentList "/x $ProductCode /qn" -Wait -ErrorAction Stop
					Write-Host "  msiexec uninstall attempted for $ProductCode"
				} catch {
					Write-Host "  Failed to run msiexec uninstall for ${ProductCode}: $($_.Exception.Message)"
				}
			}
			
			
			$WmiProductCodes = @()
			if ($WmiProducts -and $WmiProducts.Count -gt 0) {
				$WmiProductCodes = $WmiProducts | ForEach-Object { $_.IdentifyingNumber }
			}

			$AllProductCodes = $KnownProductCodes + $WmiProductCodes

			foreach ($ProductCode in $AllProductCodes) {
				$RegistryPaths = @(
					"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$ProductCode",
					"HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$ProductCode"
				)
				foreach ($Path in $RegistryPaths) {
					if (Test-Path $Path) {
						Write-Host "  Removing uninstall registry key: $Path"
						try {
							Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
							Write-Host "  Removed successfully"
						} catch {
							Write-Host "  Failed to remove: $($_.Exception.Message)"
						}
					}
				}
			}

			$AdditionalRegistryPaths = @(
				"HKCU:\\Software\\ScreenConnect",
				"HKLM:\\Software\\ScreenConnect",
				"HKLM:\\Software\\WOW6432Node\\ScreenConnect"
			)
			foreach ($Path in $AdditionalRegistryPaths) {
				if (Test-Path $Path) {
					Write-Host "  Removing registry key: $Path"
					try {
						Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
						Write-Host "  Removed successfully"
					} catch {
						Write-Host "  Failed to remove: $($_.Exception.Message)"
					}
				}
			}

			# Remove lftover files 
			$InstallDirs = @(
				"C:\\Program Files\\ScreenConnect Client*",
				"C:\\Program Files (x86)\\ScreenConnect Client*"
			)
			foreach ($Dir in $InstallDirs) {
				$ResolvedDirs = Get-ChildItem -Path $Dir -Directory -ErrorAction SilentlyContinue
				foreach ($ResolvedDir in $ResolvedDirs) {
					Write-Host "  Removing directory: $($ResolvedDir.FullName)"
					try {
						Remove-Item -Path $ResolvedDir.FullName -Recurse -Force -ErrorAction Stop
						Write-Host "  Directory removed"
					} catch {
						Write-Host "  Failed to remove directory: $($_.Exception.Message)"
					}
				}
			}

			# Remove service 
			$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:CWScreenConnectThumbprint)"
			if (Test-Path $ServiceKey) {
				try {
					Remove-Item -Path $ServiceKey -Recurse -Force -ErrorAction Stop
					Write-Host "  Service registry key removed"
				} catch {
					Write-Host "  Failed to remove service registry key: $($_.Exception.Message)"
				}
			} else {
				Write-Host "  Service registry key not found: $ServiceKey"
			}
			
			Start-Sleep -Seconds 5
			$IsInstalled = Test-IsScreenConnectInstalled
			if (-not $IsInstalled) {
				Write-Host "  Uninstall successful after forced removal."
			} else {
				Write-Host "  Uninstall still unsuccessful after forced removal."
			}
		}
	}
	
    $IsInstalled = Test-IsScreenConnectInstalled
    if ($IsInstalled) {
        Write-Host "  Uninstall appears unsuccessful"
        # Restarting service so we can log in if needed but hiding it so it doesn't clutter the log
        $Arguments = "/c Start-Service `"$ServiceName`""
        $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
    } else {
        Write-Host "  Uninstall appears successful"
    }
}

# Upgrade action
function Upgrade-ScreenConnect {
    Write-Host "Starting upgrade"
    # Check if upgrade needed
    Write-Host "  Checking version"
	
	$ScreenConnectExePath = Join-Path $InstallBasePath "ScreenConnect.ClientService.exe"
	
	# Make sure ScreenConnect executable exists before trying to retrieve the version
	if (Test-Path $ScreenConnectExePath) {
		$InstalledVersionString = (Get-Item $ScreenConnectExePath).VersionInfo.FileVersion
		$InstalledVersion = [version]$InstalledVersionString
	} else {
		Write-Host "  Unable to find executable path, exiting"
		exit 1
	}	
    
	if ($IsOverrideEnabled) {
		Write-Host "  Override found, ignoring version check and continuing"
	} else {
		# Pulling version from ScreenConnect website
		$Url = "https://docs.connectwise.com/ScreenConnect_Documentation/ScreenConnect_release_notes"
		
		# Download the HTML content of the page
		try {
			$HtmlContent = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop
		} catch { 
			Write-Host "  Failed to retrieve version release notes: $($_.Exception.Message)"
			exit 1
		}
		
		if (-not $HtmlContent.Content) {
			Write-Host "  Release notes content is empty, potential network or parsing issue"
			exit 1
		}
		
		# Define the regex pattern to match the version format
		$Pattern = "\b\d{4}\.\d{1,2}\.\d{1,2}\b"
		
		# Search for the pattern in the HTML content
		$Matches = [regex]::Matches($HtmlContent.Content, $Pattern)
		
		# Extract the most current stable version 
		if ($Matches.Count -gt 0) {
			
			$VersionObjects = $Matches | ForEach-Object { [version]$_.Value }
			$CurrentStableVersion = ($VersionObjects | Sort-Object -Descending)[0]
			
			Write-Output "  Current Stable Version: $CurrentStableVersion"
			Write-Output "  Installed Version: $InstalledVersion"
		   
			if ($InstalledVersion -eq $CurrentStableVersion) {
				Write-Host "  $ProductName version ($InstalledVersion) matches target version ($CurrentStableVersion), nothing to do"
				exit 0
			} else {
				Write-Host "  $ProductName version ($InstalledVersion) doesn't match target version ($CurrentStableVersion), continuing"
			}
		} else {
			Write-Output "  No stable version found. Exiting script."
			exit 0
		}
	}	
	
	
    # Download install file
    Download-Installer
   
    # Stop the service and processes to unlock the files
    Write-Host "  Stopping service before update"
	if (Stop-SCService) {
		Write-Host "  Service has stopped, continuing"
	} else { 
		Write-Host "  Service is still running, exiting script"
		exit 1
	}
	if (Stop-SCProcesses) {
		Write-Host "  Processes have stopped"
	} else {
		Write-Host "  One or more processes failed to stop"
		exit 1
	}

    # Extract files from MSI
    Write-Host "  Extracting upgrade files"
	$ScriptDir = (Get-Location).path 
    $StagingDir = Join-Path $ScriptDir 'staging'
	$SevenZipPath = Join-Path $ScriptDir '7z.exe'
	$InstallerPath = Join-Path $ScriptDir $InstallerFile 
	
	if (-not (Test-Path $SevenZipPath)) {
		Write-Host "  7z.exe not found in $SevenZipPath. Exiting script."
		exit 1
	}
	
    try {
        $ExtractFiles = & $SevenZipPath e $InstallerPath "-o$StagingDir" -y -bse0 -bsp0 -bso0 # disables all output
    }
    catch {
        Write-Host "  Extraction failed, exiting script"
        Write-Host "  Error: $_.Exception.Message"
        if (-not $IsOverrideEnabled) {
            rm .\$InstallerFile # Cleaning up
        }
        exit 1
    }
    if (Test-Path -Path $StagingDir -ErrorAction SilentlyContinue)  {
        Write-Host "  Extraction successful, continuing"
    } else {
        Write-Host "  Extraction failed, exiting script"
        Write-Host "  Error: $_.Exception.Message"
        if (-not $IsOverrideEnabled) {
            rm .\$InstallerFile # Cleaning up
        }
        exit 1
    }
    
	# Copy required files to staging
    Write-Host "  Copying existing configuration"
	
	# Currently unused, may be needed in the future
	<#
    $CopyConf = (Get-Location).path + '\staging\system.config'
    Copy-Item -Path (Join-Path $InstallBasePath "system.config") -Destination $CopyConf -Force
    $CopyResource = (Get-Location).path + '\staging\Client.en-US.resources'
    Copy-Item -Path (Join-Path $InstallBasePath "Client.en-US.resources") -Destination $CopyResource -Force
	#>
	
    # Transform EXE
    $StagingPath = Join-Path (Get-Location) 'staging'
    $TransFrom = Join-Path $StagingPath 'ServiceExeWithService'
    $TransTo = 	Join-Path $StagingPath 'ScreenConnect.ClientService.exe'
    Move-Item -Path $TransFrom -Destination $TransTo
    # Copy staging to production
    Write-Host "  Upgrading files"
    $FromFolder = Join-Path $StagingPath '*'
    $ToFolder = $InstallBasePath
    Write-Host "  Copy from $FromFolder"
    Write-Host "  Upgrading $ToFolder"
    try {
        $CopyProcess = Copy-Item -Path $FromFolder -Destination $ToFolder -Recurse -Force -ErrorAction Stop
        Write-Host "  Copy to production successful"
    }
    catch {
        Write-Host "  Copying to production failed: $_.Exception.Message"
        Write-Host "  Continuing script to recover"
    }
    # Start service
    Write-Host "  Restarting service"
    Start-Service $ServiceName
    try {
        $StartService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "  Error while starting service: $_.Exception.Message"
    }
    if ($StartService.Status -eq 'Running') {
        Write-Host "  Service has started"
    } else {
        Write-Host "  Service has not started: $_.Exception.Message"
        exit 1
    }
    # Update version in HKLM using EXE version
    Write-Host "  Updating version in registry"
	$FoundVersion = (Get-Item $ScreenConnectExePath).VersionInfo.FileVersion

    Write-Host "  Version $FoundVersion found in files"
    $UninstallCode = (Get-Package -Name $ServiceName).FastPackageReference
    Write-Host "  Registry entry is $UninstallCode"
    try { 
        $WriteReg = Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallCode" -Name "DisplayVersion" -Value $FoundVersion -ErrorAction Stop
        Write-Host "  Version written to registry"
    } 
    catch {
        Write-Host "  Writing to registry failed"
    }
    # Clean up files
    Write-Host "  Cleaning up files"
    if (-not $IsOverrideEnabled) {
        Remove-Item * -Exclude *ps1 -Recurse
    }
	Write-Host "  Done"
}

# === PREFLIGHT CHECKS === #
if ($IsOverrideEnabled) {
    Write-Host "Skipping preflight checks"
} else {
    Write-Host "Starting preflight checks"
    # Make sure we're working with elevated rights
    if (-not (Test-IsElevated)) {
        Write-Host "  Not Admin. Please run with Administrator privileges."
        exit 1
    } else {
        Write-Host "  Elevated privs confirmed, continuing script"
    }

    # Make sure we can write and delete
    try {
        $TestWrite = New-Item -Path "test.txt" -ItemType File -ErrorAction SilentlyContinue # Hiding output to not clutter the screen
        $TestWrite = rm test.txt -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "  Unable to write or delete in the target directory, exiting script"
        exit 1
    }
    Write-Host "  Able to write and delete in target directory, continuing script"

    # Check if it's already installed, using service instead of uninstall because we care more about files on drive
    $IsInstalled = Test-IsScreenConnectInstalled
    if ($IsInstalled) {
        Write-Host "  $ProductName is installed"
    } else {
        Write-Host "  $ProductName is not installed"
    }
    Write-Host "  Done"
}

# === ACTIONS === #
Write-Host "Starting action"
switch ($env:ScriptAction) {
    "install" {
        if ($IsInstalled -and -not $IsOverrideEnabled) {
            Write-Output "  $ProductName already installed, nothing to do"
        } else {
            Install-ScreenConnect
        }
    }
    "uninstall" {
        if ($IsInstalled -or $IsOverrideEnabled) {
            Uninstall-ScreenConnect
        } else {
            Write-Output "  $ProductName not installed, nothing to do"
        }
    }
    "upgrade" {
        if ($IsInstalled -or $IsOverrideEnabled) {
            Upgrade-ScreenConnect
        } else {
            Write-Output "  $ProductName not installed, nothing to upgrade"
        }
    }
    default {
        Write-Output "No valid action provided, exiting script"
    }
}

# === ERROR REPORTING === #
# Not implemented
Write-Host "Script completed"
