###############################################################################
# @brief This script was designed by 1mm0rt41PC.
#        It harden automaticaly Server against many attacks
#        It enable the local firewall to avoid latteral movement.
# @author https://github.com/1mm0rt41PC
###############################################################################
# TEST ONLY
$REMOTE_database="$(pwd)\logs"
# In prod, store logs into a central log like:
#$REMOTE_database="\\log-storage.domain.lo)\logs$"



###############################################################################
###############################################################################
###############################################################################



$date_raw = Get-Date
$date = $date_raw.ToString('yyyy-MM-dd-HH-mm-ss')
mkdir -Force C:\Windows\Logs\ZeroTrust | Out-Null
if( $PSVersionTable.PSVersion.Major -ge 5 ){
	Start-Transcript -Force -IncludeInvocationHeader -Append ("C:\Windows\Logs\ZeroTrust\ZT-ExportLogFWToCalculator_"+(Get-Date -Format "yyyy-MM-dd")+".log")
}else{
	Start-Transcript -Force -Append ("C:\Windows\Logs\ZeroTrust\ZT-ExportLogFWToCalculator_"+(Get-Date -Format "yyyy-MM-dd")+".log")
}


###############################################################################
# Show pretty status
function head( $title )
{
	Write-Host -BackgroundColor Blue -ForegroundColor White "[*] $title"
}


###############################################################################
# Remove invalid or old rule
function FWRemoveBadRules
{
	head "Remove invalid or old rule"
	@(
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System',
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules'
	) | foreach {
		Write-Host ">    [*] Working on $_"
		$hive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($_ -Replace 'HKLM\:\\', ''), $true)
		if( $hive -eq $null ){
			continue
		}
		$hive.GetValueNames() | where {-not $hive.GetValue($_).Contains("[AutoHarden-$date]") -and -not $hive.GetValue($_).Contains("[AutoHarden]") } | foreach {
			$v = $hive.GetValue($_)
			Write-Host ">    [*] Delete $_ => $v"
			$hive.DeleteValue($_) | Out-Null
		}
	}
}


###############################################################################
# Get file content even with file lock
function getFile( [string] $pFilename )
{
	if( (Get-Item $pFilename).length -le 0 ){
		return ''
	}
	$tmp1 = cat -ErrorAction SilentlyContinue $pFilename
	if( [String]::IsNullOrWhiteSpace($tmp1) ){
		Write-Host ">    [!] log is empty !? Trying to copy the file to temp"
		$tmpMerge = ("{0}\system32\logfiles\firewall\ZeroTrust_{1}.merge" -f $env:windir, (-join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})))
		cp -Force $pFilename $tmpMerge | Out-Null
		$tmp1 = cat -ErrorAction SilentlyContinue $tmpMerge
		rm -Force $tmpMerge | Out-Null
		if( [String]::IsNullOrWhiteSpace($tmp1) ){
			throw "Empty"
		}
	}
	return $tmp1
}


###############################################################################
head "Forward firewall log"
###############################################################################
# Move logs
$rotateFile = "${REMOTE_database}\${env:COMPUTERNAME}_${date}_pfirewall.log"
$wfLog = '';
$isFile = 0
# Rotate logs to avoid locked files
netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log-2.staging"
mv -Force $env:systemroot\system32\LogFiles\Firewall\pfirewall.log $env:systemroot\system32\LogFiles\Firewall\pfirewall.log.staging -ErrorAction SilentlyContinue
mv -Force $env:systemroot\system32\LogFiles\Firewall\pfirewall.log.old $env:systemroot\system32\LogFiles\Firewall\pfirewall.log.old.staging -ErrorAction SilentlyContinue
netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

@("pfirewall.log.staging","pfirewall.log.old.staging","pfirewall.log-2.staging","pfirewall.log-2.old.staging","ZeroTrust.staging") | foreach {
	$log = "${env:windir}\system32\logfiles\firewall\$_"
	Write-Host "[*] Reading $log"
	if( [System.IO.File]::Exists($log) ){
		$isFile += 1
		try {
			$wfLog += getFile $log
			Write-Host ">    [*] Data grabbed"
		}catch{
		}
		$wfLog += "`r`n"
		Write-Host ">    [*] Remove / Clear old log"
		rm -Force -ErrorAction SilentlyContinue $log
	}else{
		Write-Host ">    [!] File not found !"
	}
}
if( $isFile -gt 0 ){
	try{
		$wfLog | Out-File -FilePath $rotateFile -Encoding ASCII
	}catch{
		$wfLog | Out-File -Append -FilePath $env:windir\system32\logfiles\firewall\ZeroTrust.staging -Encoding ASCII
	}
}else{
	echo "Log are not enabled !!! logs doesn't exist" | Out-File -FilePath "${rotateFile}.LOG-NOT-ENABLED" -Encoding ASCII
}



###############################################################################
head "Enable firewall evt logging"
#   Modification de la stratégie de plateforme de filtrage,{0CCE9233-69AE-11D9-BED3-505054503030}
auditpol /set /subcategory:"{0CCE9233-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable

#   Rejet de paquet par la plateforme de filtrage,{0CCE9225-69AE-11D9-BED3-505054503030} == "Filtering Platform Packet Drop"
auditpol /set /subcategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable

#   Connexion de la plateforme de filtrage,{0CCE9226-69AE-11D9-BED3-505054503030} == "Filtering Platform Connection"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:enable /failure:disable



###############################################################################
head "Set firewall"
try{
	$myPS1 = ("{0}\{1}.ps1"-f $REMOTE_database,$env:COMPUTERNAME)
	###############################################################################
	Write-Host -BackgroundColor DarkGreen "Checking if rules in $myPS1"
	if( [String]::IsNullOrWhiteSpace( (cat -ErrorAction SilentlyContinue $myPS1) ) ){
		throw "NO PS1"
	}
	
	Write-Host -BackgroundColor DarkGreen "[*] Running $myPS1"
	powershell -exec bypass -nop -File $myPS1
	
	Write-Host -BackgroundColor DarkGreen "[*] PS1 ended"
}catch{
	###############################################################################
	Write-Host -BackgroundColor DarkRed "[!] Unable to read/find FW rules"
	Write-Host -BackgroundColor DarkRed "[*] Wide open the firewall remote"
	# Restart firewall
	netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
	netsh advfirewall set allprofiles settings localfirewallrules enable | Out-Null
	netsh advfirewall set allprofiles settings localconsecrules enable | Out-Null
	netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
	netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
	mkdir -Force C:\Windows\system32\LogFiles\Firewall | Out-Null
	netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" | Out-Null
	netsh advfirewall set allprofiles logging maxfilesize 32767 | Out-Null
	netsh advfirewall set allprofiles state on | Out-Null

	FWRemoveBadRules
}
