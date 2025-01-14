We created this overly complex script to install, upgrade, and uninstall ScreenConnect due to issues we found with existing scripts and ScreenConnect being unable to upgrade itself with ThreatLocker in play. Most of the problems come from ScreenConnect hashes changing between versions and clients. ScreenConnect bakes the client information into the installed files so that it can have multiple instances installed at the same time, but this is also a headache for ThreatLocker (or any allow listing platform).

For installing ScreenConnect, using a self-signed certicate works fine with ThreatLocker. Uninstall works fine as well. For automated upgrades within ScreenConnect, the downloaded EXE extracts a MSI that isn't signed and has a randomized name. We got around this by using this script, ran by DRMM, to pull down the MSI update, extracting the files, and overwriting the existing install. 

.REQUIREMENTS

This script requires 7zip to be installed. We download 7zip alongside the script in our RMM, so you'll need to do the same or something similar.

.VARIABLES

CWScreenConnectThumbprint: Set at Global level in DRMM. Identifies the ScreenConnect instance. Found in ScreenConnect.

CWScreenConnectBaseUrl: Set at Global level in DRMM. URL of our ScreenConnect instance.

CWScreenConnectInstallerUrl: URL of the ScreenConnect installer. Set at the Client level. This ensures ScreenConnect bakes in the correct variables.

CWScreenConnectusrUDF: UDF where we'll put the ScreenConnect link. Set at the Global level.

CWScreenConnectCurrentVersion: Version of ScreenConnect we're aiming for. Set at Global level.

.EXAMPLE OUTPUT

Control/ScreenConnect Installer [WIN]

Starting script

Version 4.0

Variables received from DRMM

  Thumbprint: REDACTED
  
  Base URL: REDACTED
  
  Installer URL: REDACTED
  
  UDF: 11
  
  Target Version: 24.3.7.9067
  
  Action: upgrade
  
  Script: C:\ProgramData\CentraStage\Packages\REDACTED\command.ps1

Setting functions

  Done

Starting preflight checks

  Elevated privs confirmed, continuing script
  
  Able to write and delete in target directory, continuing script
  
  ScreenConnect is installed
  
  Done

Starting upgrade

  Checking version
  
  ScreenConnect version (23.2.9.8466) doesn't match target version (24.3.7.9067), continuing
  
  Downloading install file
  
  Using TLS1.3
  
  REDACTED.ClientSetup.msi downloaded
  
  Stopping service before update
  
  Service has stopped, continuing
  
  Extracting upgrade files
  
  Extraction successful, continuing
  
  Copying existing configuration
  
  Upgrading files
  
  Copy from C:\ProgramData\CentraStage\Packages\REDACTED\staging\*
  
  Upgrading C:\Program Files (x86)\ScreenConnect Client (REDACTED)
  
  Copy to production successful
  
  Restarting service
  
  Service has started
  
  Updating version in registry
  
  Version 24.3.7.9067 found in files
  
  Registry entry is {REDACTED}
  
  Version written to registry
  
  Cleaning up files

Script completed
