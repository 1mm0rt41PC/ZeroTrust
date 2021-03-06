###############################################################################
# @brief This script was designed by 1mm0rt41PC.
#        It harden automaticaly Server against many attacks
#        It enable the local firewall to avoid latteral movement.
# @author https://github.com/1mm0rt41PC
###############################################################################
# @warning THIS SCRIPT IS AUTOGENERATED ! ALL CHANGE WILL BE REMOVED
# @date 2022-02-25-22-17-52
###############################################################################		
# Computed rules:
# 

$rule=@{
    Action = "Allow";
    Direction = "Inbound";
    RemoteAddress = @(

    "10.1.30.0/24",
    "10.250.250.1",
    "192.168.1.0-192.168.1.20"

    );
    Group = "ADMIN-ACCESS";
    DisplayName = "[AutoHarden-2022-02-25-22-17-52] ADMIN-ACCESS";
}
New-NetFirewallRule -Enabled True -Profile Any @rule -ErrorAction Continue | Out-Null

mkdir $env:windir\system32\logfiles\firewall -Force | Out-Null
Write-Host -BackgroundColor DarkGreen "[*] Enable WF with strict mode"
Set-NetFirewallProfile -All -Enabled True -NotifyOnListen False -DefaultOutboundAction Allow -DefaultInboundAction Block -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast True -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\firewall\pfirewall.log" -LogMaxSizeKilobytes 32767
Write-Host -BackgroundColor Blue -ForegroundColor White "[*] Remove invalid or old rule"
@(
	'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
	'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System',
	'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules'
) | foreach {
	Write-Host ('>    [d] Working on {0}' -f $_) ;
	$hive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($_ -Replace 'HKLM\:\\', ''), $true);
	if( $hive -eq $null ){
		continue;
	} ;
	$hive.GetValueNames() | where {
		-not $hive.GetValue($_).Contains('[AutoHarden]') -and
		-not $hive.GetValue($_).Contains('[AutoHarden-2022-02-25-22-17-52]')
	} | foreach {
		$v = $hive.GetValue($_) ;
		Write-Host ('>    [d] Delete {0} => {1}' -f $_,$v)
		$hive.DeleteValue($_) | Out-Null
	} ;
}

