<#
.DESCRIPTION
This script installs ScreenConnect on endpoints. 
It's been hacked together from multiple scripts and our own code to make the most reliable installer possible and get around issues with ThreatLocker blocking the randomized MSI produced by ScreenConnect.
There is loads of output and checks because it makes it easier for me to diagnose issues in the script when working with remote endpoints.

.VERSION
5.5

.AUTHORS
John Miller - Internetek
Caleb Schmetzer - Internetek

.RESOURCES
https://www.reddit.com/r/ConnectWiseControl/comments/vwut4k/silently_deploy_the_connectwise_control_agent/
https://www.ninjaone.com/script-hub/automate-connectwise-screenconnect-deployment-with-powershell/

.OPTIONS
Action: Tells the script which action we're taking (install or uninstall)

.VARIABLES
CWScreenConnectThumbprint: Set at Global level in DRMM. Identifies the ScreenConnect instance and verifies the installer.
CWScreenConnectBaseUrl: Set at Global level in DRMM. URL of our ScreenConnect instance.
CWScreenConnectInstallerUrl: URL of the ScreenConnect installer. Set at the Client level.
CWScreenConnectusrUDF: UDF where we'll put the ScreenConnect link. Set at the Global level.
#>

Write-Host "Starting script"
# === SETTING AND ENUMERATING VARIABLES === #
Write-Host "Version 5.2" # Reported to make sure DRMM is using the current version
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
	return Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:CWScreenConnectThumbprint)"
}

# Stops ScreenConnect service and reports result
function Stop-SCService {
    try {
        $SCServices = Get-Service | Where-Object { $_.Name -like $ServiceName }
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

# Deletes ScreenConnect service and reports result
function Delete-SCService {
	try {
        $SCService = Get-Service | Where-Object { $_.Name -like $ServiceName }
        if ($SCService) {
			sc.exe delete $ServiceName
            return $true
        } else {
            Write-Host "  No ScreenConnect Client services found."
            return $false
        }
    } catch {
        Write-Host "  Error deleting ScreenConnect service: $($_.Exception.Message)"
        return $false
    }
}

# Stops all processes associated with ScreenConnect
function Stop-SCProcesses {
    # Get all processes that start with "ScreenConnect"
    $Processes = Get-Process | Where-Object { $_.Name -like $ServiceName }
    if (-not $Processes) {
        Write-Host "  No ScreenConnect processes found."
        return $true
    }

    $AllStopped = $true
    foreach ($Process in $Processes) {
        try {
            Write-Host "  Stopping process: '$($Process.Name)' (ID: $($Process.Id))"
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
        Write-Warning "  TLS 1.2 or TLS 1.3 isn't supported on this system. This download may fail"
		return $null
    }
}

# Downloads the ScreenConnect installer
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
        Write-Host "  Download failed: $($_.Exception.Message)"
        if ($PrimaryTls -eq [System.Net.SecurityProtocolType]::Tls13) {
            Write-Host "  Retrying with TLS1.2"
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerFile
                if (-not (Test-Path -Path $InstallerFile)) {
                    throw "  File download failed on second attempt"
                }
            } catch {
                Write-Error "  Second attempt failed: $($_.Exception.Message)"
                exit 1
            }
        } else {
            exit 1
        }
    }
    Write-Host "  '$InstallerFile' downloaded"
}

# Validates the installation files (for troubleshooting)
function Validate-MSI {
	param([string]$InstallerPath) 

 	Write-Host "  Validating installer file"
	if (-not (Test-Path $InstallerPath)) {
		Write-Host "  Installer file wasn't found at '$InstallerPath'"
 		return $false
	}

	$InstallerSize = (Get-Item $InstallerPath).Length
	if ($InstallerSize -lt 1MB) {
 		Write-Host "  Installer file is less than 1MB, the download has likely failed"
   		return $false
	}  	

 	Write-Host "  Installer file validated"
  	return $true
}

# Install action
function Install-ScreenConnect {
    Write-Host "Starting install"
    
	# Calling download function
    Download-Installer
 	
  	# Validating MSI
 	if (-not (Validate-MSI $InstallerFile)) {
  		Write-Host "  Installer file validation failed, exiting with error"
		exit 1
	}
 	
    # Installing file
    if ($IsOverrideEnabled) {
       Write-Host "  Override called, using MSI Transform"
	#$Arguments = "/i $InstallerFile TRANSFORMS=""InstallOverride.mst"" /qn /norestart /l ""$InstallerLogFile"""
        $Arguments = "/i `"$InstallerFile`" /qn /norestart /l `"$InstallerLogFile`""
    } else {
        $Arguments = "/i `"$InstallerFile`" /qn /norestart /l `"$InstallerLogFile`""
    }
    $Process = (Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -Passthru)
    switch ($Process.ExitCode) {
        0 { Write-Host "  Install appears successful" }
        3010 { Write-Host "  Install appears successful. Reboot required to complete installation" }
        1641 { Write-Host "  Install appears successful. Installer has initiated a reboot" }
		1618 { Write-Host "  Installer cannot start. Windows Installer service is busy with another installation or update" }
  		1619 { Write-Host "  Installer cannot start. Windows Installer could not open the installation package" }
        default {
			Write-Host " Exit code: $($Process.ExitCode)"
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
	
    if (($Process.ExitCode -ne 0) -and ($Process.ExitCode -ne 3010)) {
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
		
		# Writing link to DRRM UDF
        Write-Host "Creating link in UDF"
        Create-JoinLink
    } else {
        Write-Host "  Service doesn't exist, exiting script with error"
        exit 1
    }
}

# Uninstall action
function Uninstall-ScreenConnect {
    Write-Host "Starting uninstall"
    Write-Host "  Stopping $ServiceName service"

    # Stopping service and processes, supposed to help with uninstall
    if (Stop-SCService) {
        Write-Host "  Service has stopped"
    } else { 
        Write-Host "  Service is still running"
    }
	
	Write-Host "  Deleting $ServiceName service"
	
	if (Delete-SCService) {
		Write-Host "  Service has been deleted"
	} else { 
        Write-Host "  Service was not deleted"
    }

	Write-Host "  Stopping ScreenConnect processes"
	
    if (Stop-SCProcesses) {
        Write-Host "  Processes have stopped"
    } else {
        Write-Host "  One or more processes failed to stop"
    }

    $UninstallCompleted = $false

    # Attempt uninstall using Method #1
    Write-Host "  Attempting registry string uninstall"

    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($Path in $UninstallPaths) {
        Get-ChildItem $Path -ErrorAction SilentlyContinue | ForEach-Object {
            $App = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($App.DisplayName -like $ServiceName -and $App.UninstallString) {
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
                    Write-Host "  Warning: executable '$ExePath' not found in path, skipping"
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

                Write-Host "  Executing uninstall: '$ExePath $Arguments'"
                try {
                    Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -ErrorAction Stop
                    Write-Host "  Registry uninstall command executed"
                } catch {
                    Write-Host "  Registry uninstall failed: $($_.Exception.Message)"
                }

                Start-Sleep -Seconds 5

                if (-not (Test-IsScreenConnectInstalled)) {
                    Write-Host "  Uninstall was successful using registry string method"
                    $UninstallCompleted = $true
                    break
                } else {
                    Write-Host "  ScreenConnect still installed, trying next path"
                }
            }
        }

        if ($UninstallCompleted) { break }
    }

    # Attempt uninstall using Method #2
    if (-not $UninstallCompleted) {
        Write-Host "  Attempting Get-Package uninstall"
        try {
            $Packages = Get-Package | Where-Object { $_.Name -like $ServiceName }
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
            Write-Host "  Uninstall was successful using the Get-Package method"
            $UninstallCompleted = $true
        } else {
            Write-Host "  ScreenConnect still installed after Get-Package uninstall"
        }
    }

    $IsInstalled = Test-IsScreenConnectInstalled
    if ($IsInstalled) {
        Write-Host "  Uninstall appears unsuccessful"
        # Restarting service so we can log in if needed but hiding it so it doesn't clutter the log
        $Arguments = "/c Start-Service `"$ServiceName`""
        $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
		exit 1
    } else {
        Write-Host "  Uninstall appears successful"
    }
}

# === PREFLIGHT CHECKS === #
if ($IsOverrideEnabled) {
    Write-Host "Skipping preflight checks"
} else {
    Write-Host "Starting preflight checks"
    # Make sure we're working with elevated rights
    if (-not (Test-IsElevated)) {
        Write-Host "  Not Admin. Please run with Administrator privileges"
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

    # Check if ScreenConnect already installed, using service instead of uninstall because we care more about files on drive
    $IsInstalled = Test-IsScreenConnectInstalled
    if ($IsInstalled) {
        Write-Host "  '$ProductName' is installed"
    } else {
        Write-Host "  '$ProductName' is not installed"
    }
    
	Write-Host "  Preflight Checks completed"
}

# === ACTIONS === #
Write-Host "Starting action"
switch ($env:ScriptAction) {
    "install" {
        if ($IsInstalled -and -not $IsOverrideEnabled) {
            Write-Host "  '$ProductName' already installed, nothing to do"
        } else {
            Install-ScreenConnect
        }
    }
    "uninstall" {
        if ($IsInstalled -or $IsOverrideEnabled) {
            Uninstall-ScreenConnect
        } else {
            Write-Host "  '$ProductName' not installed, nothing to do"
        }
    }
    default {
        Write-Host "No valid action provided, exiting script"
		exit 1
    }
}

Write-Host "Script completed"
