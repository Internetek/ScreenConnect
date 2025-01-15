<#
.DESCRIPTION
This script installs ScreenConnect on endpoints. 
It's been hacked together from multiple scripts and our own code to make the most reliable installer possible and get around issues with ThreatLocker blocking the randomized MSI produced by ScreenConnect.
There is loads of output and checks because it makes it easier for me to diagnose issues in the script when working with remote endpoints.

.VERSION
4.0

.AUTHOR
John Miller - Internetek

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
CWScreenConnectCurrentVersion: Version of ScreenConnect we're aiming for. Set at Global level.
SERVICE_CLIENT_LAUNCH_PARAMETERS=""$InstallerParameters"": Deprecated, supposed to pass install parameters to the MSI.

#>
write-host "Starting script"
# === SETTING AND ENUMERATING VARIABLES === #
write-host "Version 4.0" # Reported to make sure DRMM is using the current version
write-host "Variables received from DRMM"
write-host "  Thumbprint: $env:CWScreenConnectThumbprint"
write-host "  Base URL: $env:CWScreenConnectBaseUrl"
write-host "  Installer URL: $env:CWScreenConnectURL"
write-host "  UDF: $env:CWScreenConnectusrUDF"
write-host "  Target Version: $env:CWScreenConnectCurrentVersion"
write-host "  Action: $env:ScriptAction"
write-host "  Script: $PSCommandPath" # So we can find the working dir for diagnostics
$ProductName = "ScreenConnect" # Name of the software we're working with
$InstallerFile = "Internetek.ClientSetup.msi" # Generic name so we can call it in the script
$InstallerLogFile = "InstallLog.txt" # Dumps the install log so we can see what went wrong
$DownloadURL = $env:CWScreenConnectURL # Changing specific to generic for DownloadInstaller function

# === FUNCTIONS === #
write-host "Setting functions"
# Checks if we're working with elevated credentials
function Test-IsElevated {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Creates a JoinLink in DRMM under the provided UDF
function CreateJoinLink {
    $null = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:CWScreenConnectThumbprint)" -Name ImagePath).ImagePath -Match '(&s=[a-f0-9\-]*)'
    $GUID = $Matches[0] -replace '&s='
    $apiLaunchUrl= "$($env:CWScreenConnectBaseUrl)" + "Host#Access///" + $GUID + "/Join"
    New-ItemProperty -Path "HKLM:\Software\CentraStage" -Name "Custom$env:usrUDF" -PropertyType String -Value $apiLaunchUrl -force | out-null
    write-host "  UDF written to UDF#$env:CWScreenConnectusrUDF."
}

# Downloader
function DownloadInstaller {
    write-host "  Downloading install file"
    # Which TLS versions does the endpoint support?
    $SupportedTLSversions = [enum]::GetValues([System.Net.SecurityProtocolType])
    if ($SupportedTLSversions -contains [System.Net.SecurityProtocolType]::Tls13) {
        Write-Output "  Using TLS1.3"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
    } elseif ($SupportedTLSversions -contains [System.Net.SecurityProtocolType]::Tls12) {
        Write-Output "  Using TLS1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    } else {
        Write-Warning "  TLS 1.2 or TLS 1.3 isn't supported on this system. This download may fail!"
    }
    # Download the file
    try {
        Invoke-WebRequest -Uri $DownloadURL -OutFile $InstallerFile
        if (-not (Test-Path -Path $InstallerFile)) {
            throw "  File download failed"
        }
    } catch {
        Write-Error "  Download failed: $_"
        if ($SupportedTLSversions -contains [System.Net.SecurityProtocolType]::Tls13) {
            Write-Output "Retrying with TLS1.2"
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $DownloadURL -OutFile $InstallerFile
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
    write-host "Starting install"
    # Calling download function, gimme files
    DownloadInstaller
    # Installing file
    $Arguments = "/i $InstallerFile /qn /norestart /l ""$InstallerLogFile"""
    $Process = (Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -Passthru)
    switch ($Process.ExitCode) {
        0 { Write-Host "  Install appears successful" }
        3010 { Write-Host "  Install appears successful. Reboot required to complete installation" }
        1641 { Write-Host "  Install appears successful. Installer has initiated a reboot" }
        default {
            write-host "  Exit code does not indicate success, dumping log:"
            write-host "  +++++++++++++++++++++++++++++++++"
            Get-Content $InstallerLogFile -ErrorAction SilentlyContinue | Select-Object -Last 50 | Write-Host
            write-host "  +++++++++++++++++++++++++++++++++"
        }
    }
    # Delete install file so we don't clutter up the drive
    write-host "Cleaning up"
    try {
        rm .\$InstallerFile -ErrorAction Stop
        write-host "  File deleted"
    } catch {
        write-host "  Failed to delete file" 
        write-host " " $_.Exception.Message
    }
    if ($Process.ExitCode -ne 0) {
        write-host "Install appears to have failed, exiting script"
        exit 1
    }
    # Make sure it started
    write-host "Checking install success"
    # Get service status
    Write-host "  Getting Service status"
    $StartService = Get-Service -Name "ScreenConnect Client ($env:CWScreenConnectThumbprint)" -ErrorAction SilentlyContinue
    If ($StartService.length -gt 0) {
        If ($StartService.Status -eq 'Running') {
            Write-host "  Service exists and is started"
        } else {
            write-host "  Service exists but is not started, attempting to start service"
            Start-Service "ScreenConnect Client ($env:CWScreenConnectThumbprint)"
        }
        write-host "Creating link in UDF"
        # Writing link to DRRM UDF
        CreateJoinLink
    } else {
        Write-Host "  Service doesn't exist, exiting script with error"
        exit 1
    }
}

# Uninstall action
function Uninstall-ScreenConnect {
    write-host "Starting uninstall"
    write-host "  Stopping service"
    # Stopping service, supposed to help with uninstall
    try {
        Stop-Service "ScreenConnect Client ($env:CWScreenConnectThumbprint)"
    } catch {
        write-host "  Couldn't stop service: $_.Exception.Message"
    }
    # Reporting if it worked
    $StopService = Get-Service -Name "ScreenConnect Client ($env:CWScreenConnectThumbprint)" -ErrorAction SilentlyContinue
    If ($StopService.Status -ne 'Running') {
        Write-host "  Service has stopped"
    } else {
        write-host "  Service is still running"
    }
    # Attempt uninstall
    write-host "  Attempting uninstall"
    try {
        Get-Package -Name "ScreenConnect Client ($env:CWScreenConnectThumbprint)" | Uninstall-Package | out-null
    } catch {
        write-host "  Failed to uninstall: $_.Exception.Message"
    }
    # Wait for a bit to make sure uninstall completed
    sleep 15
    # Check if it shows installed
    $IsInstalled = (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:CWScreenConnectThumbprint)")
    if ($IsInstalled) {
        write-host "  Uninstall appears unsuccessful"
        # Restarting service so we can log in if needed but hiding it so it doesn't clutter the log
        $Arguments = "/c Start-Service ""ScreenConnect Client ($env:CWScreenConnectThumbprint)"""
        $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
    } else {
        write-host "  Uninstall appears successful"
    }
}

# Upgrade action
function Upgrade-ScreenConnect {
    write-host "Starting upgrade"
    # Check if upgrade needed
    write-host "  Checking version"
    $InstalledVersion = (Get-Item 'C:\Program Files (x86)\ScreenConnect Client (919d3745b4e34229)\ScreenConnect.ClientService.exe').VersionInfo.FileVersion
    if ($env:CWScreenConnectCurrentVersion -eq $InstalledVersion) {
        write-host "  $ProductName version ($InstalledVersion) matches target version ($env:CWScreenConnectCurrentVersion), nothing to do"
        exit 0
    } else {
        write-host "  $ProductName version ($InstalledVersion) doesn't match target version ($env:CWScreenConnectCurrentVersion), continuing"
    }
    # Download install file
    DownloadInstaller
    # Stop the service to unlock the files
    write-host "  Stopping service before update"
    try {
        Stop-Service "ScreenConnect Client ($env:CWScreenConnectThumbprint)"
    } catch {
        write-host "  Couldn't stop service: $_.Exception.Message"
    }
    $StopService = Get-Service -Name "ScreenConnect Client ($env:CWScreenConnectThumbprint)" -ErrorAction SilentlyContinue
    If ($StopService.Status -ne 'Running') {
        write-host "  Service has stopped, continuing"

    } else {
        write-host "  Service is still running, exiting script"
        exit 1
    }
    # Extract files from MSI
    write-host "  Extracting upgrade files"
    $StagingDir = (get-location).path +'\staging'
    try {
        $ExtractFiles = .\7z.exe e .\$InstallerFile -oStaging -y -bse0 -bsp0 -bso0 # disables all output
    }
    catch {
        write-host "  Extraction failed, exiting script"
        write-host "  Error: $_.Exception.Message"
        rm .\$InstallerFile # Cleaning up
        exit 1
    }
    if ((Test-Path -Path $StagingDir -ErrorAction SilentlyContinue) -eq "True") {
        write-host "  Extraction successful, continuing"
    } else {
        write-host "  Extraction failed, exiting script"
        write-host "  Error: $_.Exception.Message"
        rm .\$InstallerFile # Cleaning up
        exit 1
    }
    # Copy required files to staging
    write-host "  Copying existing configuration"
    $CopyConf = (get-location).path + '\staging\system.config'
    Copy-Item -Path "C:\Program Files (x86)\ScreenConnect Client ($env:CWScreenConnectThumbprint)\system.config" -Destination $CopyConf -Force
    $CopyResource = (get-location).path + '\staging\Client.en-US.resources'
    Copy-Item -Path "C:\Program Files (x86)\ScreenConnect Client ($env:CWScreenConnectThumbprint)\Client.en-US.resources" -Destination $CopyResource -Force
    # Transform EXE
    $TransFrom = (get-location).path + '\staging\ServiceExeWithService'
    $TransTo = (get-location).path + '\staging\ScreenConnect.ClientService.exe'
    Move-Item -Path $TransFrom -Destination $TransTo
    # Copy staging to production
    write-host "  Upgrading files"
    $FromFolder = (get-location).path + '\staging\*'
    $ToFolder = "C:\Program Files (x86)\ScreenConnect Client ($env:CWScreenConnectThumbprint)"
    write-host "  Copy from $FromFolder"
    write-host "  Upgrading $ToFolder"
    try {
        $CopyProcess = Copy-Item -Path $FromFolder -Destination $ToFolder -Recurse -Force -ErrorAction Stop
        write-host "  Copy to production successful"
    }
    catch {
        write-host "  Copying to production failed: $_.Exception.Message"
        write-host "  Continuing script to recover"
    }
    # Start service
    write-host "  Restarting service"
    Start-Service "ScreenConnect Client ($env:CWScreenConnectThumbprint)"
    try {
        $StartService = Get-Service -Name "ScreenConnect Client ($env:CWScreenConnectThumbprint)" -ErrorAction SilentlyContinue
    }
    catch {
        write-host "  Error while starting service: $_.Exception.Message"
    }
    If ($StartService.Status -eq 'Running') {
        Write-host "  Service has started"
    } else {
        write-host "  Service has not started: $_.Exception.Message"
        exit 1
    }
    # Update version in HKLM using EXE version
    write-host "  Updating version in registry"
    $FoundVersion = (Get-Item "C:\Program Files (x86)\ScreenConnect Client ($env:CWScreenConnectThumbprint)\ScreenConnect.ClientService.exe").VersionInfo.FileVersion
    write-host "  Version $FoundVersion found in files"
    $UninstallCode = (Get-Package -Name "ScreenConnect Client ($env:CWScreenConnectThumbprint)").FastPackageReference
    write-host "  Registry entry is $UninstallCode"
    try { 
        $WriteReg = Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallCode" -Name "DisplayVersion" -Value $FoundVersion -ErrorAction Stop
        write-host "  Version written to registry"
    } 
    catch {
        write-host "  Writing to registry failed"
    }
    # Clean up files
    write-host "  Cleaning up files"
    Remove-Item * -Exclude *ps1 -Recurse
}
write-host "  Done"

# === PREFLIGHT CHECKS === #
write-host "Starting preflight checks"
# Make sure we're working with elevated rights
if (-not (Test-IsElevated)) {
    write-host "  Not Admin. Please run with Administrator privileges."
    exit 1
} else {
    write-host "  Elevated privs confirmed, continuing script"
}

# Make sure we can write and delete
try {
    $TestWrite = New-Item -Path "test.txt" -ItemType File -ErrorAction SilentlyContinue # Hiding output to not clutter the screen
    $TestWrite = rm test.txt -ErrorAction SilentlyContinue
}
catch {
    write-host "  Unable to write or delete in the target directory, exiting script"
    exit 1
}
write-host "  Able to write and delete in target directory, continuing script"

# Check if it's already installed, using service instead of uninstall because we care more about files on drive
$IsInstalled = (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ScreenConnect Client ($env:CWScreenConnectThumbprint)")
if ($IsInstalled) {
    write-host "  $ProductName is installed"
    $Installed = "True"
} else {
    write-host "  $ProductName is not installed"
    $Installed = "False"
}
write-host "  Done"

# === ACTIONS === #
write-host "Starting action"
switch ($env:ScriptAction) {
    "install" {
        if (-not $Installed) {
            Install-ScreenConnect
        } else {
            Write-Output "  $ProductName already installed, nothing to do"
        }
    }
    "uninstall" {
        if ($Installed) {
            Uninstall-ScreenConnect
        } else {
            Write-Output "  $ProductName not installed, nothing to do"
        }
    }
    "upgrade" {
        if ($Installed) {
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
write-host "Script completed"
