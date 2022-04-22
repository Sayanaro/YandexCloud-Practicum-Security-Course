#ps1
# ^^^ 'ps1' is only for cloudbase-init, some sort of sha-bang in linux

# logging
Start-Transcript -Path "$ENV:SystemDrive\provision.txt" -IncludeInvocationHeader -Force
"Bootstrap script started" | Write-Host

$MyAdministratorPlainTextPassword = "${ admin_pass }"
$ADDSIP = "${ adds_ip }"

# inserting value's from terraform
if (-not [string]::IsNullOrEmpty($MyAdministratorPlainTextPassword)) {
    "Set local administrator password" | Write-Host
    $MyAdministratorPassword = $MyAdministratorPlainTextPassword | ConvertTo-SecureString -AsPlainText -Force
    # S-1-5-21domain-500 is a well-known SID for Administrator
    # https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
    $MyAdministrator = Get-LocalUser | Where-Object -Property "SID" -like "S-1-5-21-*-500"
    $MyAdministrator | Set-LocalUser -Password $MyAdministratorPassword
}

$outScript = "`$DomanName = `"yp-lab.edu`"`r`n

`$outNull = Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled `"false`" -Confirm:`$false
`$outNull = Set-TimeZone -Id `"Russian Standard Time`" -Confirm:`$false

if (!(Test-Path `"C:\Work`")) {
    `$outNull = New-Item -Path `"C:\`" -Name Work -ItemType Directory
}

`$IPAddress = Get-NetIPAddress -AddressFamily IPv4 | where {`$_.InterfaceAlias -notlike `"*Loopback*`"}
`$Gateway = (Get-NetIPConfiguration).IPv4DefaultGateway
`$outNull = Remove-NetIPAddress -InterfaceIndex `$IPAddress.InterfaceIndex -Confirm:`$false
`$outNull = New-NetIPAddress -IPAddress `$IPAddress.IPAddress -DefaultGateway `$Gateway.NextHop -PrefixLength `$IPAddress.PrefixLength -InterfaceIndex `$IPAddress.InterfaceIndex
`$outNull = Set-DNSClientServerAddress -InterfaceIndex `$IPAddress.InterfaceIndex -ServerAddresses `"$ADDSIP`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/RootCA.cer`" -Destination `"C:\work`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/SubCA.cer`" -Destination `"C:\work`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/SubCA.crl`" -Destination `"C:\work`"
Start-BitsTransfer -Source `"https://raw.githubusercontent.com/Sayanaro/YandexCloud-Prcticum-Security-Course/master/data/SubCA+.crl`" -Destination `"C:\work`"

Import-Certificate -FilePath C:\work\RootCA.cer -CertStoreLocation Cert:\LocalMachine\Root\
Import-Certificate -FilePath C:\work\SubCA.cer -CertStoreLocation Cert:\LocalMachine\CA\
certutil -addstore -f CA C:\work\SubCA.crl
certutil -addstore -f CA C:\work\SubCA+.crl

Add-LocalGroupMember -Group `"Remote Desktop Users`" -Member `"NT AUTHORITY\Authenticated Users`"
Start-BitsTransfer -Source `"http://dl.google.com/chrome/install/375.126/chrome_installer.exe`" -Destination `"C:\Work`"
cd C:\work\
.\chrome_installer.exe /silent /install
Add-WindowsFeature RSAT-AD-Tools,RSAT-DNS-Server -IncludeAllSubFeature -Confirm:`$false

`$Resolve = Resolve-DnsName -Name `"fs.yp-lab.edu`" -ErrorAction SilentlyContinue

if(!`$Resolve) {
    while(!`$Resolve) {
        Start-Sleep 5
        `$Resolve = Resolve-DnsName -Name `"fs.yp-lab.edu`" -ErrorAction SilentlyContinue
    }
}

`$AdminPassword = ConvertTo-SecureString `"$MyAdministratorPlainTextPassword`" -AsPlainText -Force
[pscredential]`$Cred = New-Object System.Management.Automation.PSCredential (`"yp-lab\Administrator`", `$AdminPassword)
Add-Computer -Domain yp-lab.edu -Credential `$Cred -Restart"

$outScript | Out-File -FilePath "C:\Windows\Setup\Scripts\SetupComplete.ps1" -Confirm:$false -Force
$outScript = "powershell.exe -ExecutionPolicy Bypass -File `"C:\Windows\Setup\Scripts\SetupComplete.ps1`""
$outScript | Out-File -FilePath "C:\Windows\Setup\Scripts\SetupComplete.cmd" -Encoding ascii -Confirm:$false -Force

"Bootstrap script ended" | Write-Host