# Guide: Fixing Leftover Product Codes in ScreenConnect
Sometimes Get-Package doesn't uninstall every trace of ScreenConnect on a system, causing future installations to fail due to old product codes being detected by the MSI installer. The error will look similar to this: 

``` plaintext
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

**The problematic line in question is here: `Found old product code: {B62FCF0D-D9C5-4F42-AFC1-EF8369FD0D04}`**

## Step #1: Run the `ScreenConnect Lingering Installations Search` component on the endpoint. 

You should get an output similar to this: 


![Image is not displaying](https://github.com/Internetek/ScreenConnect/blob/98e2b7e8e1a6de38c6335e111edd8cf1239a8808/Guide%20Images/lingeringinstallationsearchexamples.png)

Take note of these two lines:
  - `Uninstall Key Found: {B62FCF0D-D9C5-4F42-AFC1-EF8369FD0D04} - DisplayName: ScreenConnect Client (919d3745b4e34229)`
  - `Installer Product Found: D0FCF26B5C9D24F4FA1CFE3896DFD040 - ProductName: ScreenConnect Client (919d3745b4e34229)`

The Uninstall Key **{B62FCF0D-D9C5-4F42-AFC1-EF8369FD0D04}** is the problematic product code.
The Installer Product **D0FCF26B5C9D24F4FA1CFE3896DFD040** is the compressed version of the above product code. Write down both the product code and it's compressed version somewhere. You will need them for the next step.

> Note: In some cases you may have multiple product and compressed codes. You need to save them all.

## Step #2: Run the `ScreenConnect Lingering Product Code Fix` component on the endpoint. 

Put the product code/s you found into the `ProblemProductCodes` variable and the compressed code/s into the `ProblemCompressedCodes` variable. If you have multiple of each code, write a list using commas (with **no** spaces) in the variables. An example is shown below:


![Image is not displaying](https://github.com/Internetek/ScreenConnect/blob/1500ba0978901f9659bdd6af168e113673f04c12/Guide%20Images/runproductcodefixexample.png)


After running the component, you should get an output showing you that your codes were successfully deleted: 


![Image is not displaying](https://github.com/Internetek/ScreenConnect/blob/357a6bfef283a6a8e2560173051fd73c949c76c7/Guide%20Images/successfulproductcodefixexample.png)


## Step #3: Try to reinstall ScreenConnect. 


The exit code should either indicate that the install was successful or that the install was successful but a reboot is required to complete it. If the install needed a reboot, there is a very good chance that the Join Link was not created and written properly to the UDF. Proceed to Step #4 if this is the case.


## Step #4: Run the 'ScreenConnect Join Link Fix' on the endpoint. 

Once the Join Link Fix has finished, ScreenConnect should be successfully installed on the endpoint.
