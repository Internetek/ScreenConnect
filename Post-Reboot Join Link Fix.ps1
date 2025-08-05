<#
.DESCRIPTION
This script should be run after a ScreenConnect install that required a reboot
to create the Join Link in DRMM using registry values from the installed client

.VARIABLES
CWScreenConnectThumbprint: Set at Global level in DRMM
CWScreenConnectBaseUrl: Set at Global level in DRMM
CWScreenConnectusrUDF: UDF number to write Join Link into
#>

Write-Host "Starting post-reboot Join Link creation"

# Set service name
$ServiceName = "ScreenConnect Client ($env:CWScreenConnectThumbprint)"

# Check service status
Write-Host "- Getting service status: $ServiceName"
$StartService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($StartService.Length -gt 0) {
    if ($StartService.Status -eq 'Running') {
        Write-Host "- Service exists and is started"
    } else {
        Write-Host "- Service exists but is not started, attempting to start service"
        try {
            Start-Service $ServiceName -ErrorAction Stop
            Write-Host "- Service started successfully"
        } catch {
            Write-Host "- Failed to start service: $($_.Exception.Message)"
            exit 1
        }
    }

    # Create Join Link
    Write-Host "Creating link in UDF"
    try {
        $ServiceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $ImagePath = (Get-ItemProperty -Path $ServiceRegPath -Name ImagePath -ErrorAction Stop).ImagePath
        if ($ImagePath -match '(&s=[a-f0-9\-]+)') {
            $Guid = $Matches[0] -replace '&s='
            $JoinLink = "$($env:CWScreenConnectBaseUrl)Host#Access///$Guid/Join"
            $UdfKeyPath = "HKLM:\Software\CentraStage"
            $UdfName = "Custom$env:CWScreenConnectusrUDF"

            New-ItemProperty -Path $UdfKeyPath -Name $UdfName -PropertyType String -Value $JoinLink -Force | Out-Null
            Write-Host "- UDF#$env:CWScreenConnectusrUDF updated successfully."
        } else {
            Write-Host "- Failed to extract GUID from ImagePath."
            exit 1
        }
    } catch {
        Write-Host "- Error creating Join Link: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "- Service doesn't exist, exiting with error"
    exit 1
}
