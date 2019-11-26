
#Get Start Time
$startDTM = (Get-Date)


Write-Host ""


if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   

Start-Process powershell -Verb runAs  

}
else 
{
    Write-Host "***************************************************************************** Welcome to our Windows Auditing Script ***************************************************************"  -ForegroundColor Red
    Write-Host ""
    Write-Host " 
    this script is brought to you by:
    Armel KEPJIO KAMWA
    Daniel BARBIER
    " -BackgroundColor Black

    Write-Host ""
    write-host ""

} 



#region 2

#operating system, service pack and architecture information
write-host "*** 2. Showing operating system, service pack and architecture information ***" -ForegroundColor Green
Write-Host ""

get-wmiobject win32_operatingsystem | select-object Caption, OSArchitecture, servicepackmajorversion, servicepackminorversion | Format-List

write-host ""
write-host ""

#endregion





#region 3

write-host "3." -ForegroundColor Green

#local account informations
write-host "** Showing local accounts information **" -ForegroundColor Green
Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount=$True" 

#last login for each user
$user = Get-LocalUser
write-host "** Showing last login for each user **" -ForegroundColor Green
write-host " Last Login : " -ForegroundColor Magenta
ForEach ($use in $user) {
    Write-Host " Last Login of $use : " ($use).lastlogon
}
Write-Host ""    


#passwordexpires and password that must be changed in less than one week
write-host "** Write in the log file the expired ones and those whose password must be changed in less than one week **" -ForegroundColor Green

Get-WmiObject -class win32_useraccount -filter "passwordexpires=$true" | Select-Object name | Out-File -FilePath C:\log.txt 
Write-Host "* you can find your log file in disk C: *" -ForegroundColor DarkGreen

 $SevenDayWarnDate = (get-date).adddays(7).ToLongDateString()
 $SixDayWarnDate = (get-date).adddays(6).ToLongDateString()
 $FiveDayWarnDate = (get-date).adddays(5).ToLongDateString()
 $FourDayWarnDate = (get-date).adddays(4).ToLongDateString()
 $ThreeDayWarnDate = (get-date).adddays(3).ToLongDateString()
 $TwoDayWarnDate = (get-date).adddays(2).ToLongDateString()
 $OneDayWarnDate = (get-date).adddays(1).ToLongDateString()
 
 
 if (($user).passwordexpires -eq $SevenDayWarnDate){
     $user | Select-Object name, passwordexpires  >> D:\log.txt
    }
    if (($user).passwordexpires -eq $SixDayWarnDate){
        $user | Select-Object name, passwordexpires >> D:\log.txt 
       }
       if (($user).passwordexpires -eq $FiveDayWarnDate){
        $user | Select-Object name, passwordexpires >> D:\log.txt 
       }
       if (($user).passwordexpires -eq $FourDayWarnDate){
        $user | Select-Object name, passwordexpires >> D:\log.txt  
       }
       if (($user).passwordexpires -eq $ThreeDayWarnDate){
        $users | Select-Object name, passwordexpires >> D:\log.txt 
       }
       if (($user).passwordexpires -eq $TowDayWarnDate){ 
        $user | Select-Object name, passwordexpires >> D:\log.txt  
       }
       if (($user).passwordexpires -eq $OneDayWarnDate){
        $users | Select-Object name, passwordexpires >> D:\log.txt 
       }
 

Write-Host ""

#check of UAC settings
write-host "** Checking for User Account Contol (UAC) settings : **" -ForegroundColor Green
Write-Host -NoNewline " I check the registry key to check if UAC is enabled or disabled : " -ForegroundColor Yellow
(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA

write-host ""
write-host ""

#endregion






#region 4

#directories in PATH environment variable
write-host "*** 4. Checking directories in PATH environment variable ***" -ForegroundColor Green
$env:Path

write-host ""
write-host ""

#endregion

   




#region 5

#Retrieving ACLs for winlogon, LSA, secure pipe servers, knownDLLs, AllowedPATHS, and RPC
write-host "*** 5. Retrieving ACLs for winlogon, LSA, secure pipe servers, knownDLLs, AllowedPATHS, and RPC ***" -ForegroundColor Green
Write-Host ""

Get-Acl -Path hklm:\SOFTWARE\Microsoft\"Windows NT"\CurrentVersion\Winlogon, 
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa, 
hklm:\SYSTEM\CurrentControlSet\Control\"Session Manager"\KnownDLLs, 
hklm:\SYSTEM\CurrentControlSet\Control\SecurePipeServers,
hklm:\SOFTWARE\Microsoft\Rpc, hklm:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths 

write-host ""
write-host ""

#endregion






#region 6

#check installed security product	
write-host "*** 6. Checking for installed security products: product name, virus definition state, size of threat database, ***" -ForegroundColor Green
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

Write-Host ""
Write-Host ""

#endregion







#region 7

write-host "7." -ForegroundColor Green
Write-Host ""

#information about firewall
write-host "** Information about the firewall: firewall profile, number of rules, third party firewalls **" -ForegroundColor Green
Get-NetFirewallRule | Select-Object * | ft
Write-Host ""

#firewall logging, logging file,packet drops
write-host "** Activate firewall logging, check the ACLs on the logging file and show the total number of packet drops **" -ForegroundColor Green
Set-NetFirewallProfile -Name Domain -LogBlocked True
Get-Acl c:\windows\system32\LogFiles\Firewall\pfirewall.log  | select * | fl

Write-Host ""
Write-Host ""

#endregion






#region 8


write-host "*** 8. Checking AppLocker status and policies and checking device guard status ***" -ForegroundColor Green
Write-Host ""

#applocker status
write-host "** Checking AppLocker status and policies **"  -ForegroundColor Green
Write-Host ""
write-host "* we can see on an outgridview window applocker status and policies *"  -ForegroundColor Green

$apps = Get-BitLockerVolume | Select-Object MountPoint
Get-AppLockerPolicy -Effective -XML > C:\Effective.xml
ForEach ($app in $apps){
Get-ChildItem -Path $app.MountPoint -Filter * -Recurse -ErrorAction Ignore | Convert-Path -ErrorAction Ignore | 
Test-AppLockerPolicy -XMLPolicy C:\Effective.xml -ErrorAction Ignore | 
out-gridview  -Title "$app"
}
Write-Host ""

#device guard status
write-host "** checking device guard status **"  -ForegroundColor Green
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

Write-Host ""
Write-Host ""
 #endregion









 #region 9

write-host "*** 9. Enumerating exposed local filesystem shares. Start a quick scan on these shares. Show the file extensions present in each share ***" -ForegroundColor Green
write-host ""

#exposed local filesystem shares
write-host "** Enumerating exposed local filesystem shares **" -ForegroundColor Green
get-smbshare | fl

$path = Get-SmbShare | select Path
foreach ($scan in $path) {
    if($scan.Path) {
        
        #scan on the shares
       Start-MpScan -ScanPath $scan.Path -ScanType QuickScan 
         
       #file extensions present in each share
       write-host "** File extensions present in $scan **" -ForegroundColor Green
        Get-ChildItem $scan.Path | select Extension -Unique | ft
     }
}


Write-Host ""
Write-Host ""

 #endregion

















#region 10

write-host "*** 10. Checking BitLocker status on all volumes and permissions on NTFS drives ***" -ForegroundColor Green
Write-Host ""

#bitlocker status
write-host "** Checking BitLocker status on all volumes **" -ForegroundColor Green
Get-BitLockerVolume | ft

#permission on NTFS drives
write-host "** Checking permissions on NTFS drives **"  -ForegroundColor Green

$perms = Get-BitLockerVolume | Select-Object MountPoint
ForEach ($perm in $perms) {
Get-NTFSAccess -path $perm.MountPoint 
}

Write-Host ""
Write-Host ""
Write-Host ""

 #endregion














#region 11

write-host "*** 11. Enumerating installed certificated and expiring date of each one ***"  -ForegroundColor Green
write-host ""
Write-Host "** the NotAfter represent the expiring date of each certificates **" -ForegroundColor Green

get-childitem -Path Cert:\LocalMachine -Recurse | Select-Object pspath, pschildname, psdrive, psprovider, NotAfter | Format-Table

write-host ""
write-host ""

#endregion









 #region 12

# Echo Time elapsed
$endDTM = (Get-Date)
write-host "Elapsed Time of this script : $(($endDTM-$startDTM).totalseconds) seconds"

 #endregion

