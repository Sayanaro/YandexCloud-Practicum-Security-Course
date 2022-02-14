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

`$outScript = `"powershell.exe -ExecutionPolicy Bypass -File C:\Stages\StageService3.ps1`"
`$outScript | Out-File -FilePath `"C:\Stages\StageService3.bat`" -Encoding ascii -Confirm:`$false -Force

`$outScript = `"powershell.exe -ExecutionPolicy Bypass -File C:\Stages\StageService2.ps1`"
`$outScript | Out-File -FilePath `"C:\Stages\StageService2.bat`" -Encoding ascii -Confirm:`$false -Force

`$IPAddress = Get-NetIPAddress -AddressFamily IPv4 | where {`$_.InterfaceAlias -notlike `"*Loopback*`"}
`$Gateway = (Get-NetIPConfiguration).IPv4DefaultGateway
`$outNull = Remove-NetIPAddress -InterfaceIndex `$IPAddress.InterfaceIndex -Confirm:`$false
`$outNull = New-NetIPAddress -IPAddress `$IPAddress.IPAddress -DefaultGateway `$Gateway.NextHop -PrefixLength `$IPAddress.PrefixLength -InterfaceIndex `$IPAddress.InterfaceIndex
`$outNull = Set-DNSClientServerAddress -InterfaceIndex `$IPAddress.InterfaceIndex -ServerAddresses `"127.0.0.1`",`$IPAddress.IPAddress

`$RegArgLoadSystemHive = `"HKLM\System`"
`$RegServicesPath = `"HKLM:\System\ControlSet001\Services\`"
`$RegStageService = `$RegServicesPath + `"StageService\`"
`$RegStageServiceEnum = `$RegStageService + `"Enum\`"
`$VHDSystemHive = `"C:\WINDOWS\SYSTEM32\CONFIG\SYSTEM`"
`$RegStageServiceParameters = `$RegStageService + `"Parameters\`"
`$RegStageServiceSecurity = `$RegStageService + `"Security\`"


. reg load `"`$RegArgLoadSystemHive`" `$VHDSystemHive
Start-Sleep -Seconds 5

`$supress = New-Item -Path `$RegServicesPath -Name StageService
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-Item -Path $`RegStageService -Name Enum
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-Item -Path `$RegStageService -Name Parameters
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-Item -Path `$RegStageService -Name Security
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageService -Name Type -PropertyType Dword -Value 16
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageService -Name Start -PropertyType Dword -Value 2
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageService -Name ErrorControl -PropertyType Dword -Value 1
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageService -Name WOW64 -PropertyType Dword -Value 1
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageService -Name DisplayName -PropertyType String -Value 'StageService'
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageService -Name ObjectName -PropertyType String -Value 'LocalSystem'
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageService -Name ImagePath -PropertyType ExpandString -Value 'C:\Stages\srvany.exe'
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageServiceEnum -Name '0' -PropertyType String -Value 'Root\LEGACY_StageService\0000'
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageServiceEnum -Name Count -PropertyType Dword -Value 1
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageServiceEnum -Name NextInstance -PropertyType Dword -Value 1
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageServiceParameters -Name Application -PropertyType String -Value 'C:\Stages\StageService2.bat'
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = New-ItemProperty -Path `$RegStageServiceSecurity -Name Security -PropertyType Binary -Value ([byte[]](0x01,0x00,0x14,0x80,0xb8,0x00,0x00,0x00,0xc4,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x02,0x00,0x1c,0x00,0x01,0x00,0x00,0x00,0x02,0x80,0x14,0x00,0xff,0x01,0x0f,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0xfd,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0xff,0x01,0x0f,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00,0x00,0x00,0x14,0x00,0x8d,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x04,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x8d,0x01,0x02,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x06,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,0x01,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x0b,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0xfd,0x01,0x02,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x23,0x02,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00))
[gc]::collect()
Start-Sleep -Seconds 5
`$supress = Set-ItemProperty -Path `"`$(`$RegServicesPath)ParPort`" -Name Start -Value 4
[gc]::collect()
Start-Sleep -Seconds 5
[gc]::collect()

. reg unload `$RegArgLoadSystemHive

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