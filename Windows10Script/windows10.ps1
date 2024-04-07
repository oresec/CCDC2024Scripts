If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
# firewall
Set-ItemProperty -Path “HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy” -Name Enabled -Value 0 -Force
netsh advfirewall import "$env:USERPROFILE\Desktop\Windows10Script\firewall.wfw"
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
netsh advfirewall firewall set rule name="netcat" new enable=no
 
# New-Item -ItemType directory -Path '\Desktop\Windows10LGPO\{09093B37-C80C-42A5-814A-4719224A5639}'
Copy-Item -Path "$env:USERPROFILE\Desktop\Windows10Script\LGPO.exe" -Destination "C:\Windows\System32"
lgpo /g "$env:USERPROFILE\Desktop\Windows10Script\Win10"

#Set automatic updates
ECHO "Setting updates to automatic..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

# set auditing
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

# user password settings
net accounts /minpwlen:10 /maxpwage:30 /minpwage:1 /uniquepw:24
net accounts /lockoutthreshold:6 /lockoutwindow:30 /lockoutduration:30

# Reset folder and file perms to default in /Users folder
icacls \Users /reset /t


# Set all user passwords
Get-WmiObject win32_useraccount | Foreach-Object {
$ua = ([adsi](“WinNT://”+$_.caption).replace(“\”,”/”))
$ua.SetPassword("BlasterR0x123!")
}

ECHO "Disabled Users:"
Get-WmiObject -class Win32_UserAccount -Filter "Disabled='True'"
ECHO "Locked Out Users:"
Get-WmiObject -class Win32_UserAccount -Filter "Lockout='True'"
ECHO "Administrators:"
Get-LocalGroupMember -Group "Administrators"
ECHO "Media Files:"
cd C:\
Get-ChildItem -Path C:\Users -Include *.mp3, *.mp4, *.txt, *.jpeg, *.png, *.tiff, *.bmp, *.wav, *.avi, *.mov, *.pdf, *.doc, *.docx, *.csv, *.ppt, *.pptx, *.gif -File -Recurse -Force -ErrorAction SilentlyContinue > 'C:\mediafiles.txt'


# Services
Enable-WindowsOptionalFeature –FeatureName Internet-Explorer-Optional-amd64 -All –Online
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Disable-WindowsOptionalFeature -Online -FeatureName SmbDirect
Disable-WindowsOptionalFeature -Online -FeatureName telnetClient
Disable-WindowsOptionalFeature -Online -FeatureName TFTP
Disable-WindowsOptionalFeature -Online -FeatureName NetTcpPortSharing
# IIS
Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
Disable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
Disable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
Disable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
Disable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment

Disable-WindowsOptionalFeature -online -FeatureName NetFx4Extended-ASPNET45
Disable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45

Disable-WindowsOptionalFeature -Online -FeatureName IIS-HealthAndDiagnostics
Disable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging
Disable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries
Disable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor
Disable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing
Disable-WindowsOptionalFeature -Online -FeatureName IIS-Security
Disable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering
Disable-WindowsOptionalFeature -Online -FeatureName IIS-Performance
Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerManagementTools
Disable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility
Disable-WindowsOptionalFeature -Online -FeatureName IIS-Metabase
Disable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole
Disable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
Disable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
Disable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent
Disable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument
Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets
Disable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit
Disable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions
Disable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter
Disable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic

Disable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45
Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer

# File Sharing
net share C$ /DELETE
net stop lanmanserver
# Defender
Set-ItemProperty -Path “HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender” -Name DisableAntiSpyware -Value 0 -Force
# Firewall
# Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True 
# Services Enabled
Set-Service -Name wuauserv -Status Running -StartupType Automatic # Windows Update
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
Set-Service -Name SSDPSRV -Status Stopped -StartupType Disabled
Set-Service -Name upnphost -Status Stopped -StartupType Disabled
Set-Service -Name WMSvc -Status Stopped -StartupType Disabled
Set-Service -Name WerSvc -Status Stopped -StartupType Disabled
Set-Service -Name Wecsvc-Status Stopped -StartupType Disabled
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
# Remove Known unwanted programs

#$app.Uninstall()
# disable remote desktop
$remotedesktop = Read-Host 'Do you want to disable remote desktop?'
if($remotedesktop.ToUpper() -eq 'Y') {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1
    ECHO "Removing remote desktop"
    }
else {
    ECHO "Not removing remote desktop"
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
# Firefox
Copy-Item -Path "$env:USERPROFILE\Desktop\Windows10Script\mozilla.cfg" -Destination "$env:Programfiles\Mozilla Firefox\"
Copy-Item -Path "$env:USERPROFILE\Desktop\Windows10Script\local-settings.js" -Destination "$env:Programfiles\Mozilla Firefox\defaults\pref"

PAUSE 
