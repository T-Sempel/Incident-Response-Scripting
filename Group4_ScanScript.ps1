#Written for CYB-4863-01(25/SP): ST:Incident Response, Group 4 

#References: 
# PE_Scripting_Pat_1and2_2.11.25.docx
# https://stackoverflow.com/questions/44784137/how-to-get-the-active-user-username-using-query-user
# https://www.action1.com/blog/check-missing-windows-updates-script/
# https://devblogs.microsoft.com/scripting/use-powershell-to-find-the-history-of-usb-flash-drive-usage/
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor 
# https://www.xplg.com/windows-server-security-events-list/


# o List all active users on a system. - Done
# o Identify installed software and versions. - Done
# o Check for missing security patches. - Done
# o Consider Sysinternals Suite (AutoRuns, TCP View, Process Monitor, etc.)
# o Consider NirSoft
# o Identify USB History -Done
#

#Check for Admin rights
Write-Host "`nPlease be sure to run as Admin. `n  Script continues in 5 seconds. CTRL-C to escape.`n"
Start-Sleep -Seconds 5


#Create Folder for Log Files
$WorkingPath = Get-Location
$WorkingTime = Get-Date -f yyyy-MM-dd_HH-mm
$ReportFolder = "$WorkingPath\Report_$env:computername`_$WorkingTime"
mkdir -Force $ReportFolder | Out-Null


#Dump Event Logs
Write-Host "`nDumping the last 7 days of System, Application, and PS logs to file."
$StartDate = (Get-Date).AddDays(-7)
Get-EventLog System -After $StartDate | Format-List | Out-File -FilePath $ReportFolder\System_Log.txt   
Get-EventLog Application -After $StartDate | Format-List | Out-File -FilePath $ReportFolder\Application_Log.txt    
Get-EventLog 'Windows PowerShell' -After $StartDate | Format-List | Out-File -FilePath $ReportFolder\Powershell_Log.txt   


#Dump Security Event Logs
Write-Host "`nDumping the last 7 days of Security logs to file. Filtering for higher risk alerts, minus successful logons."
$StartDate = (Get-Date).AddDays(-7)
Get-EventLog Security -After $StartDate | 
Where-Object { $_.EventID -in @(4618, 4649, 4765, 4766, 4794, 4897, 4964, 5124, 1102, 4625, 4728, 4732, 4756, 4740, 4663, 4719, 4648, 4782, 4697) } | 
Format-List | Out-File -FilePath $ReportFolder\Security_Log.txt

Write-Host "`nDumping the last 7 days of Security logs to file. Filtering for successful logons EID-4624."
$StartDate = (Get-Date).AddDays(-7)
Get-EventLog Security -After $StartDate | 
Where-Object { $_.EventID -in 4624 } | 
Format-List | Out-File -FilePath $ReportFolder\Security_Logons.txt


# Get Active Local Users. Seed from PE_Scripting_Pat_1and2_2.11.25.docx
Write-Host "`nActive Local Users:"
Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object Name, LastLogon, Enabled, Description | 
Format-Table -AutoSize

Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object Name, LastLogon, Enabled, Description | 
Format-Table -AutoSize | Out-File -FilePath $ReportFolder\Active_Local_Users.txt


#Get Logged on Users
Write-Host "`nLogged on Users"
query user 
query user | Out-File -FilePath $ReportFolder\Logged_On_Users.txt


# Installed Software and Versions. Seed from PE_Scripting_Pat_1and2_2.11.25.docx
Write-Host "`nInstalled Software:"
Get-WmiObject -Class Win32_Product | Select-Object Name, Vendor, Version | Format-Table -AutoSize

Write-Host "`nInstalled Software list writing to file."
Get-WmiObject -Class Win32_Product | Select-Object Name, Vendor, Version | Format-Table -AutoSize | 
Out-File -FilePath $ReportFolder\Installed_Software.txt


#Get missing updates. Seed from https://www.action1.com/blog/check-missing-windows-updates-script/
Write-Host "`nMissing Security Patches (Windows Update):"
(New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | 
Select-Object Title, Description, DriverModel | Format-List

Write-Host "`nMissing Security Patches (Windows Update) writing to file."
(New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | 
Select-Object Title, Description, DriverModel | Format-List | Out-File -FilePath $ReportFolder\Missing_Updates.txt


#Get USB History. Seed from https://devblogs.microsoft.com/scripting/use-powershell-to-find-the-history-of-usb-flash-drive-usage/
Write-Host "`nUSB History"
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*' | Select-Object FriendlyName, DeviceDesc, Mfg, HardwareID | 
Format-List 

Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*' | Select-Object FriendlyName, DeviceDesc, Mfg, HardwareID | 
Format-List | Out-File -FilePath $ReportFolder\USB_History.txt


#Get Any Enabled Scheduled Tasks
Write-Host "`nEnabled Scheduled Tasks"
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Out-File -FilePath $ReportFolder\Scheduled_Tasks.txt


#Get Running Services
Write-Host "`nRunning Services"
Get-Service | Where-Object {$_.Status -eq "Running"} | Format-List
Get-Service | Where-Object {$_.Status -eq "Running"} | Format-List | Out-File -FilePath $ReportFolder\Running_Services.txt


#Get Recent Installs
Write-Host "`nRecent Installation activity"
Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Format-List

Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Format-List | 
Out-File -FilePath $ReportFolder\Recent_Installs.txt


#Get Ip Info
Write-Host "`nIP Config Information"
ipconfig /all
ipconfig /all | Out-File -FilePath $ReportFolder\IP_Config.txt
Get-NetIPAddress
Get-NetIPAddress | Out-File -FilePath $ReportFolder\IP_Information.txt


#Get Active connections
Write-Host "`nActive Connections"
Get-NetTCPConnection -State Established
Get-NetTCPConnection -State Established | Out-File -FilePath $ReportFolder\Active_Connections.txt

#Start AutoRuns
.\SysInternals\Autoruns64.exe

#Start ProcessMonitor
.\SysInternals\ProcMon64.exe

#Start ProcessMonitor
.\SysInternals\ProcExp64.exe

#Start ProcessMonitor
.\SysInternals\TCPview64.exe
