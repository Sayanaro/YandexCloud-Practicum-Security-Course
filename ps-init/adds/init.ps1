#ps1
# ^^^ 'ps1' is only for cloudbase-init, some sort of sha-bang in linux

# logging
Start-Transcript -Path "$ENV:SystemDrive\provision.txt" -IncludeInvocationHeader -Force
"Bootstrap script started" | Write-Host

$outScript = "`$DSRMPassword = `"P@ssw0rd`"`r`n
`$DomanName = `"yp-lab.edu`"`r`n

try {
`$outNull = Get-NetFirewallProfile -ErrorAction stop -ErrorVariable err | Set-NetFirewallProfile -Enabled `"false`" -Confirm:`$false -ErrorAction stop -ErrorVariable err
}
catch {
    `$err.Exception | Out-File c:\PSErr.log -Append -Force -Confirm:`$false
}
`$outNull = Set-TimeZone -Id `"Russian Standard Time`" -Confirm:`$false

if (!(Test-Path `"C:\Stages`")) {
    `$outNull = New-Item -Path `"C:\`" -Name Stages -ItemType Directory
}

Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/srvany.exe`" -Destination `"C:\Stages`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/STAGES/StageService3.ps1`" -Destination `"C:\Stages`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/STAGES/StageService2.ps1`" -Destination `"C:\Stages`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/RootCA.cer`" -Destination `"C:\Stages`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/SubCA.cer`" -Destination `"C:\Stages`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/adfs.pfx`" -Destination `"C:\Stages`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/SubCA.crl`" -Destination `"C:\Stages`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/SubCA+.crl`" -Destination `"C:\Stages`"

#`$outScript = `"powershell.exe -ExecutionPolicy Bypass -File C:\Stages\StageService3.ps1`"
#`$outScript | Out-File -FilePath `"C:\Stages\StageService3.bat`" -Encoding ascii -Confirm:`$false -Force

#`$outScript = `"powershell.exe -ExecutionPolicy Bypass -File C:\Stages\StageService2.ps1`"
#`$outScript | Out-File -FilePath `"C:\Stages\StageService2.bat`" -Encoding ascii -Confirm:`$false -Force

#`$IPAddress = Get-NetIPAddress -AddressFamily IPv4 | where {`$_.InterfaceAlias -notlike `"*Loopback*`"}
#`$Gateway = (Get-NetIPConfiguration).IPv4DefaultGateway
#`$outNull = Remove-NetIPAddress -InterfaceIndex `$IPAddress.InterfaceIndex -Confirm:`$false
#`$outNull = New-NetIPAddress -IPAddress `$IPAddress.IPAddress -DefaultGateway `$Gateway.NextHop -PrefixLength `$IPAddress.PrefixLength -InterfaceIndex `$IPAddress.InterfaceIndex
`$outNull = Set-DNSClientServerAddress -InterfaceIndex `$IPAddress.InterfaceIndex -ServerAddresses `"127.0.0.1`",`$IPAddress.IPAddress

`$RegStageService = `"HKLM\System\ControlSet001\Services\StageService\`"
`$RegStageServiceEnum = `$RegStageService + `"Enum\`"
`$RegStageServiceParameters = `$RegStageService + `"Parameters\`"
`$RegStageServiceSecurity = `$RegStageService + `"Security\`"

reg add `$RegStageService
reg add `$RegStageServiceEnum
reg add `$RegStageServiceParameters
reg add `$RegStageServiceSecurity
reg add `$RegStageService /v Type /t REG_DWORD /d 16
reg add `$RegStageService /v Start /t REG_DWORD /d 2
#reg add `$RegStageService /v DelayedAutostart /t REG_DWORD /d 1
reg add `$RegStageService /v ErrorControl /t REG_DWORD /d 1
reg add `$RegStageService /v WOW64 /t REG_DWORD /d 1
reg add `$RegStageService /v DisplayName /t REG_SZ /d StageService
reg add `$RegStageService /v ObjectName /t REG_SZ /d LocalSystem
reg add `$RegStageService /v ImagePath /t REG_EXPAND_SZ /d 'C:\Stages\srvany.exe'
reg add `$RegStageServiceEnum /v 0 /t REG_SZ /d 'Root\LEGACY_StageService\0000'
reg add `$RegStageServiceEnum /v Count /t REG_DWORD /d 1
reg add `$RegStageServiceEnum /v NextInstance /t REG_DWORD /d 1
reg add `$RegStageServiceParameters /v Application /t REG_SZ /d 'C:\Stages\StageService2.bat'
reg add `$RegStageServiceSecurity /v Security /t REG_BINARY /d 01001480b8000000c4000000140000003000000002001c000100000002801400ff010f00010100000000000100000000020088000600000000001400fd01020001010000000000051200000000001800ff010f0001020000000000052000000020020000000014008d010200010100000000000504000000000014008d010200010100000000000506000000000014000001000001010000000000050b00000000001800fd01020001020000000000052000000023020000010100000000000512000000010100000000000512000000
reg delete HKLM\System\ControlSet001\Services\ParPort\ /v Start /f
reg add HKLM\System\ControlSet001\Services\ParPort\ /v Start /t REG_DWORD /d 4

`$outNull = Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools -Confirm:`$false
`$DSRM = ConvertTo-SecureString `"`$DSRMPassword`" -AsPlainText -Force
`$outNull = Install-ADDSForest -DomainName `$DomanName -InstallDNS -SafeModeAdministratorPassword `$DSRM -DomainMode Default -DomainNetbiosName `$DomanName.Substring(0, `$DomanName.IndexOf('.')) -ForestMode Default -Confirm:`$false -Force"

$outNull = New-Item -Path "C:\" -Name Stages -ItemType Directory
$outScript | Out-File -FilePath "C:\Windows\Setup\Scripts\SetupComplete.ps1" -Confirm:$false -Force
$outScript = "powershell.exe -ExecutionPolicy Bypass -File `"C:\Windows\Setup\Scripts\SetupComplete.ps1`""
$outScript | Out-File -FilePath "C:\Windows\Setup\Scripts\SetupComplete.cmd" -Encoding ascii -Confirm:$false -Force

$outScript = "powershell.exe -ExecutionPolicy Bypass -File `"C:\Stages\StageService3.ps1`""
$outScript | Out-File -FilePath "C:\Stages\StageService3.bat" -Encoding ascii -Confirm:$false -Force

$outScript = "powershell.exe -ExecutionPolicy Bypass -File `"C:\Stages\StageService2.ps1`""
$outScript | Out-File -FilePath "C:\Stages\StageService2.bat" -Encoding ascii -Confirm:$false -Force

# inserting value's from terraform
$MyAdministratorPlainTextPassword = "${ admin_pass }"
$MyAdministratorPlainTextPassword | Out-File -FilePath "C:\Stages\passwd.txt" -Confirm:$false -Force
if (-not [string]::IsNullOrEmpty($MyAdministratorPlainTextPassword)) {
    "Set local administrator password" | Write-Host
    $MyAdministratorPassword = $MyAdministratorPlainTextPassword | ConvertTo-SecureString -AsPlainText -Force
    # S-1-5-21domain-500 is a well-known SID for Administrator
    # https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
    $MyAdministrator = Get-LocalUser | Where-Object -Property "SID" -like "S-1-5-21-*-500"
    $MyAdministrator | Set-LocalUser -Password $MyAdministratorPassword
}

"Bootstrap script ended" | Write-Host