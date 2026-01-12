# ScreenConnect Troubleshooting Guide 
---
This document provides solutions for the various types of installation/uninstallation issues that we've run into while using ScreenConnect as our remote support platform. 

---

## Table of Contents

**I. General Information**

- [ScreenConnect Resources](#ScreenConnect-Resources)
- [ScreenConnect Related Components](#ScreenConnect-Related-Components)


**II. Errors**

  - ['The older version of ScreenConnect cannot be removed'](#The-older-version-of-ScreenConnect-cannot-be-removed)

  - ['ScreenConnect is already installed'](#ScreenConnect-is-already-installed)

  - ['Uninstall appears unsuccessful'](#Uninstall-appears-unsuccessful)

  - ['Windows Installer service is busy with another installation or update'](#Windows-Installer-service-is-busy-with-another-installation-or-update)

  - ['Windows Installer could not open the installation package'](#Windows-Installer-could-not-open-the-installation-package)

  - ['Object reference not set to an instance of an object'](#Object-reference-not-set-to-an-instance-of-an-object)

---

## General Information

### ScreenConnect Resources

- [Blog](https://www.screenconnect.com/blog)

- [ConnectWise Documentation](https://docs.connectwise.com/ScreenConnect_Documentation?_gl=1%2Aute08o%2A_gcl_au%2AOTM5MDkxMTkxLjE3Njc5OTExMDk.%2A_ga%2ANzMwNDE3MDM2LjE3Njc5OTExMTA.%2A_ga_QSGE0F7K8V%2AczE3Njc5OTExMDkkbzEkZzAkdDE3Njc5OTExMDkkajYwJGwwJGgyNDMzNzEzMzI.)

- [Release Notes](https://docs.connectwise.com/ScreenConnect_Documentation/ScreenConnect_release_notes?_gl=1%2Ajailsm%2A_gcl_au%2AOTM5MDkxMTkxLjE3Njc5OTExMDk.%2A_ga%2ANzMwNDE3MDM2LjE3Njc5OTExMTA.%2A_ga_QSGE0F7K8V%2AczE3NjgyNTAwMDEkbzIkZzEkdDE3NjgyNTAwOTEkajYwJGwwJGgxMTM1MzcwNzM4)

---

### ScreenConnect Related Components

- **`Control/ScreenConnect Installer/Uninstaller [WIN]`**
  - Component used for both installing and uninstalling ScreenConnect. 

- **`ScreenConnect Broken Installation Fix`**
  - Component used for fixing many of the issues with the install/uninstall process.

- **`ScreenConnect Installations Search`**
  - Component used to find all traces of ScreenConnect installations on a system without deleting them.

- **`ScreenConnect Version Check`**
  - Component used to check a user's version of ScreenConnect and compare it to the newest version.

- **`Stop MSI Installer Processes`**
  - Component is often needed during troubleshooting.

- **`ConnectWise ScreenConnect (Control) [WIN]`**
  - *Deprecated - do not use.*

- **`ConnectWise Control (ScreenConnect) Uninstaller [WIN]`**
  - *Deprecated - do not use.*

--- 

## Errors

### 'The older version of ScreenConnect cannot be removed'

Sometimes the uninstall process doesn't delete every trace of ScreenConnect on a system, causing future installations to fail due to old product codes being detected by the MSI installer. 

```plaintext
Control/ScreenConnect Installer [WIN]
Starting script
Version 5.0
Variables received from DRMM
Thumbprint: 919d3745b4e34229
Base URL: https://internetek.screenconnect.com/
Installer URL: https://internetek.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=Industrial%20Process%20Systems&c=&c=&c=&c=&c=&c=&c=
UDF: 11
Action: install
Script: C:\ProgramData\CentraStage\Packages\ccda2c12-7b2e-4fc8-b89c-71ad5e8c3252#\command.ps1
Setting functions
Skipping preflight checks
Starting action
Starting install
Downloading install file
Using TLS1.3
Internetek.ClientSetup.msi downloaded
Override called, using MSI Transform
Exit code does not indicate success, dumping log:
+++++++++++++++++++++++++++++++++
=== Logging started: 7/25/2025 16:37:07 ===
Action start 16:37:07: INSTALL.
Action start 16:37:07: FindRelatedProducts.
Action ended 16:37:07: FindRelatedProducts. Return value 1.
Action start 16:37:07: AppSearch.
Action ended 16:37:07: AppSearch. Return value 1.
Action start 16:37:07: FixupServiceArguments.
SFXCA: Extracting custom action to temporary directory: C:\Windows\Installer\MSIA603.tmp-
SFXCA: Binding to CLR version v4.0.30319
Calling custom action ScreenConnect.InstallerActions!ScreenConnect.ClientInstallerActions.FixupServiceArguments
Found old product code: {B62FCF0D-D9C5-4F42-AFC1-EF8369FD0D04}
Setting new values for e: Access
Setting new values for y: Guest
Setting new values for h: instance-iimc1o-relay.screenconnect.com
Setting new values for p: 443
Setting new values for k: BgIAAACkAABSU0ExAAgAAAEAAQDBFUr+w9N4cfPNCIAQ3BFbKT6+3Spmne+E0Ej/Boml66XUafPNOGXANWYGwR1dxBFWET3g2Nbo06VUvhcOwaXFgsxHM7EqrB8TLvxAPKhESLmenvz6khGW92HDBOJhp5Jrvu2djUfzBme4iFstWeNCVFDmNHDNTLdUIuSfoYuIuTxOuyzHi31bJX0Quwuia7rLqzyzmfQM7giyGxW0pKN3pmYUDV3lNnsAND9s18hx8kegWlufijO1iKv5MVFhPZ7mWPgemMUqCUQtTFOYb/OF7+Yy7NEoiLD+7Dvr3jnoeeRER1e4bZpViHS/l2MFXy47JMHZ7bW4jJsVFkSKxhDe
Setting new values for c: Industrial Process Systems, , , , , , ,
Action ended 16:37:07: FixupServiceArguments. Return value 1.
Action start 16:37:07: LaunchConditions.
Action ended 16:37:07: LaunchConditions. Return value 1.
Action start 16:37:07: ValidateProductID.
Action ended 16:37:07: ValidateProductID. Return value 1.
Action start 16:37:07: CostInitialize.
Action ended 16:37:07: CostInitialize. Return value 1.
Action start 16:37:07: FileCost.
Action ended 16:37:07: FileCost. Return value 1.
Action start 16:37:07: CostFinalize.
Action ended 16:37:07: CostFinalize. Return value 1.
Action start 16:37:07: InstallValidate.
Action ended 16:37:07: InstallValidate. Return value 1.
Action start 16:37:07: InstallInitialize.
Action ended 16:37:07: InstallInitialize. Return value 1.
Action start 16:37:07: RemoveExistingProducts.
CustomAction returned actual error code 1612 (note this may not be 100% accurate if translation happened inside sandbox)
MSI (s) (6C:28) [16:37:07:762]: Product: ScreenConnect Client (919d3745b4e34229) -- Error 1714. The older version of ScreenConnect Client (919d3745b4e34229) cannot be removed. Contact your technical support group. System Error 1612.

Error 1714. The older version of ScreenConnect Client (919d3745b4e34229) cannot be removed. Contact your technical support group. System Error 1612.
Action ended 16:37:07: RemoveExistingProducts. Return value 3.
Action ended 16:37:07: INSTALL. Return value 3.
MSI (s) (6C:28) [16:37:07:770]: Windows Installer installed the product. Product Name: ScreenConnect Client (919d3745b4e34229). Product Version: 25.4.20.9295. Product Language: 1033. Manufacturer: ScreenConnect Software. Installation success or error status: 1603.

=== Logging stopped: 7/25/2025 16:37:07 ===
+++++++++++++++++++++++++++++++++
Cleaning up
File deleted
Install appears to have failed, exiting script
```

**The problematic line in question is here:**  
`Found old product code: {B62FCF0D-D9C5-4F42-AFC1-EF8369FD0D04}`

**How to Fix:** 

**Step #1: Run the `Control/ScreenConnect Installer/Uninstaller [WIN]` component with the `Uninstall` action selected.**

Depending on how broken the lingering ScreenConnect installations are, this component could clear it up. If this doesn't work, proceed to the next step.

**Step #2: Run the `ScreenConnect Broken Installation Fix` component**

Make sure to use the correct thumbprint for the `TargetClientThumbprint` variable. The default one is likely correct unless you are trying to uninstall one of the agents used for remote workers. If you are unsure which client you are trying to uninstall, the component `ScreenConnect Installations Search` can be used to see all ScreenConnect agents, folders, and services on the endpoint. 

**Step #3: Try to reinstall ScreenConnect with the `Control/ScreenConnect Installer/Uninstaller [WIN]` component**

ScreenConnect should reinstall successfully at this point. 

---
### 'ScreenConnect is already installed'

Sometimes an installation will show in Datto as a success, but upon examining the logs you will see that it skipped the entire installation process with the message that ScreenConnect is already installed.

**How to Fix:** 

**Step #1: Run the `Control/ScreenConnect Installer/Uninstaller [WIN]` component with the `Uninstall` action selected.**

If this doesn't work, proceed to next step.


**Step #2: Run the `ScreenConnect Broken Installation Fix` component**

Make sure to use the correct thumbprint for the `TargetClientThumbprint` variable. The default one is likely correct unless you are trying to uninstall one of the agents used for remote workers. If you are unsure which client you are trying to uninstall, the component `ScreenConnect Installations Search` can be used to see all ScreenConnect agents, folders, and services on the endpoint. If Screenconnect still won't install afterwards, move on to the next step.

**Step #4: Use the `ScreenConnect Installations Search` component**

You may be able to figure out what exactly is remaining from old ScreenConnect installations and manually remove it to fix the issue. If ScreenConnect still won't install, or the search turned up no results, move on to the next step.

**Step #5: Run the `Control/ScreenConnect Installer/Uninstaller [WIN]` component with the 'Install' action selected and 'OverrideEnabled' option selected**

This is a last resort. This will override the existing installation check used in the script and proceed with the install anyways. 

---

### 'Uninstall appears unsuccessful'

During an uninstall, sometimes both the *Registry String* and *Get-Package* methods will fail, leading to an incomplete installation. 

**How to Fix:** 

**Step #1: Run the `ScreenConnect Broken Installation Fix` component**

Make sure to use the correct thumbprint for the `TargetClientThumbprint` variable. The default one is likely correct unless you are trying to uninstall one of the agents used for remote workers. If you are unsure which client you are trying to uninstall, the component `ScreenConnect Installations Search` can be used to see all ScreenConnect agents, folders, and services on the endpoint. 

**Step #2: Run the `ScreenConnect Installations Search` component**

This will confirm if the installation has been completely removed from the endpoint. If it hasn't, you may have to manually remove whatever the `ScreenConnect Broken Installation Fix` isn't getting.

---

### 'Windows Installer service is busy with another installation or update'

During installation, sometimes you will see the above message or `MSI Error Code 1618`. This usually occurs when
you are trying to reinstall ScreenConnect after fixing a broken installation, since the ScreenConnect install process tends to get stuck and hold up the Windows Installer.

**How to Fix:**

**Step #1: Run the `Stop MSI Installer Processes` component**

This will free up the Windows Installer service and stop any stuck ScreenConnect install processes. 

**Step #2: Try to install ScreenConnect with the `Control/ScreenConnect Installer/Uninstaller [WIN]` component**

ScreenConnect should install successfully at this point. 


---

### 'Windows Installer could not open the installation package'

Very rarely, you may see the above message or `MSI Error Code 1619`. This can be one of two things: ThreatLocker blocking the installation or the Windows Installer service being stopped. 

**How to Fix:**

**Scenario #1: ThreatLocker blocking installation**
This has to be resolved within ThreatLocker itself, likely involving a policy change. It can't be fixed or worked around using the components found in this guide. 

**Scenario #2: Stopped Windows Installer service** 
This can be easily resolved by restarting the Windows Installer service.

--- 

### 'Object reference not set to an instance of an object'

This is an overly vague way for Datto to say the script timed out. Annoyingly, this also means you 
can't see any logs generated by the script. 

**How to Fix:**

**Step #1: Run the `ScreenConnect Broken Installation Fix` component**

You want to make sure the install/uninstall script isn't timing out due to a previous install being broken. Make sure to use the correct thumbprint for the `TargetClientThumbprint` variable. The default one is likely correct unless you are trying to uninstall one of the agents used for remote workers. If you are unsure which client you are trying to uninstall, the component `ScreenConnect Installations Search` can be used to see all ScreenConnect agents, folders, and services on the endpoint. If this doesn't clear up the issue, move onto the next step.

**Step #2: Wait a while or reboot the endpoint if possible**

Oftentimes, this error is a result of performance issues from the endpoint itself and not anything ScreenConnect related. Waiting a period of time or rebooting the endpoint and trying the install/uninstall again will often alleviate the error.
