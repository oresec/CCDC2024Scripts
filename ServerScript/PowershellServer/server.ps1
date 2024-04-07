If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

#Apply LGPO policy object
#New-Item -ItemType directory -Path '$env:USERPROFILE\Desktop\PowershellServer\WindowsServer2016'
Copy-Item -Path "$env:USERPROFILE\Desktop\PowershellServer\LGPO.exe" -Destination "C:\Windows\System32"
lgpo /g "$env:USERPROFILE\Desktop\PowershellServer\WindowsServer2016"

#automatic updates
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

Get-WmiObject win32_useraccount | Foreach-Object {
([adsi](“WinNT://”+$_.caption).replace(“\”,”/”)).SetPassword(“BlasterR0x123!”)
}
ECHO "Disabled Users:"
Get-WmiObject -class Win32_UserAccount -Filter "Disabled='True'"

ECHO "Locked Out Users:"
Get-WmiObject -class Win32_UserAccount -Filter "Lockout='True'"

ECHO "Administrators:"
Get-LocalGroupMember -Group "Administrators"

ECHO "Media Files:"
cd C:\
Get-ChildItem -Path C:\Users\ -Include *.mp3, *.mp4, *.txt, *.jpeg, *.png, *.tiff, *.bmp, *.wav, *.avi, *.mov, *.pdf, *.doc, *.docx, *.csv, *.ppt, *.pptx, *.gif -File -Recurse -ErrorAction SilentlyContinue
 
$remotedesktop = Read-Host 'Do you want to disable remote desktop?'
if($remotedesktop.ToUpper() -eq'Y') {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1
    }
else {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}
$vendors = @("Apple Inc.")
foreach($vendor in $vendors){
    $app = Get-WmiObject -Class Win32_Product | Where-Object {
        $_.Vendor -match "$vendor"
    }
    $app.Uninstall()
}
# Windows Updates
Set-Service -Name wuauserv -Status Running -StartupType Automatic
Set-Service -Name EventLog -Status Running -StartupType Automatic # Event Logger (Pts from Rd 2 2019)
Set-Service -Name mpssvc -Status Running -StartupType Automatic 
Set-Service -Name WinDefend -Status Running -StartupType Automatic
Set-Service -Name wcmsvc -Status Running -StartupType Automatic
Set-Service -Name SecurityHealthService -Status Running -StartupType Manual
# Disable Services
Set-Service -Name RemoteRegistry -Status Stopped -StartupType Disabled
Set-Service -Name bthserv -Status Stopped -StartupType Disabled
Set-Service -Name Browser -Status Stopped -StartupType Disabled
Set-Service -Name MapsBroker -Status Stopped -StartupType Disabled
Set-Service -Name lfsvc -Status Stopped -StartupType Disabled
Set-Service -Name IISADMIN -Status Stopped -StartupType Disabled
Set-Service -Name irmon -Status Stopped -StartupType Disabled
Set-Service -Name SharedAccess -Status Stopped -StartupType Disabled
Set-Service -Name lltdsvc -Status Stopped -StartupType Disabled
Set-Service -Name MSiSCSI -Status Stopped -StartupType Disabled
Set-Service -Name InstallService -Status Stopped -StartupType Disabled
Set-Service -Name sshd -Status Stopped -StartupType Disabled
Set-Service -Name PNRPsvc -Status Stopped -StartupType Disabled
Set-Service -Name p2psvc -Status Stopped -StartupType Disabled
Set-Service -Name p2pimsvcy -Status Stopped -StartupType Disabled
Set-Service -Name PNRPAutoReg -Status Stopped -StartupType Disabled
Set-Service -Name wercplsupport -Status Stopped -StartupType Disabled
Set-Service -Name RpcLocator -Status Stopped -StartupType Disabled
Set-Service -Name RemoteAccess -Status Stopped -StartupType Disabled
Set-Service -Name lanmanserver -Status Stopped -StartupType Disabled
Set-Service -Name simptcp -Status Stopped -StartupType Disabled
Set-Service -Name SNMP -Status Stopped -StartupType Disabled
Set-Service -Name NetTcpPortSharing -Status Stopped -StartupType Disabled
Set-Service -Name SSDPSRV -Status Stopped -StartupType Disabled
Set-Service -Name upnphost -Status Stopped -StartupType Disabled
Set-Service -Name WMSvc -Status Stopped -StartupType Disabled
Set-Service -Name WerSvc -Status Stopped -StartupType Disabled
Set-Service -Name Wecsvc-Status -Status Stopped -StartupType Disabled
Set-Service -Name WMPNetworkSvc -Status Stopped -StartupType Disabled
Set-Service -Name icssvc -Status Stopped -StartupType Disabled
Set-Service -Name WpnService -Status Stopped -StartupType Disabled
Set-Service -Name PushToInstall -Status Stopped -StartupType Disabled
Set-Service -Name WinRM -Status Stopped -StartupType Disabled
Set-Service -Name W3SVC -Status Stopped -StartupType Disabled
Set-Service -Name XboxGipSvc -Status Stopped -StartupType Disabled
Set-Service -Name XblAuthManager -Status Stopped -StartupType Disabled
Set-Service -Name XblGameSave -Status Stopped -StartupType Disabled
Set-Service -Name XboxNetApiSvc -Status Stopped -StartupType Disabled
# File Sharing
net share C$ /DELETE
net stop lanmanserver
# Services
Enable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online # Enable Internet Explorer
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Disable-WindowsOptionalFeature -Online -FeatureName SmbDirect
Disable-WindowsOptionalFeature -Online -FeatureName telnetClient
Disable-WindowsOptionalFeature -Online -FeatureName TFTP
Disable-WindowsOptionalFeature -Online -FeatureName NetTcpPortSharing
# Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer
# Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPSvc
# Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPExtensibility
Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer
Set-MpPreference -DisableRealtimeMonitoring $false
Set-NetFirewallProfile -Enabled True
# Enable IE ESC
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1
# TO DO
# More program removal
cd $env:USERPROFILE
Copy-Item -Path "Desktop\PowershellServer\mozilla.cfg" -Destination "$env:Programfiles\Mozilla Firefox\"
Copy-Item -Path "Desktop\PowershellServer\local-settings.js" -Destination "$env:Programfiles\Mozilla Firefox\defaults\pref"
PAUSE 
