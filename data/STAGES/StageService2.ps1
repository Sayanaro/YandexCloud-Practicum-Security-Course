$DomainDN = (Get-ADDomain -Current LoggedOnUser -ErrorAction SilentlyContinue).DistinguishedName
$outNull = New-ADOrganizationalUnit -Name "Org" -Path $DomainDN -ErrorAction SilentlyContinue

$SecurePassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
Start-Sleep 15
New-ADUser -Name "Sonya Blade" -Accountpassword $SecurePassword -Enabled $true -Path "OU=Org, $DomainDN" -SamAccountName "sblade" -DisplayName "Sonya Blade" -Surname "Blade" -GivenName "Sonya" -PasswordNeverExpires $true -UserPrincipalName "sblade@yp-lab.edu" -Description "Security officer" -ErrorAction SilentlyContinue
New-ADUser -Name "Johnny Cage" -Accountpassword $SecurePassword -Enabled $true -Path "OU=Org, $DomainDN" -SamAccountName "jcage" -DisplayName "Johnny Cage" -Surname "Cage" -GivenName "Johnny" -PasswordNeverExpires $true -UserPrincipalName "jcage@yp-lab.edu" -Description "Network administrator" -ErrorAction SilentlyContinue
New-ADUser -Name "Hanzo Hasashi" -Accountpassword $SecurePassword -Enabled $true -Path "OU=Org, $DomainDN" -SamAccountName "scorpion" -DisplayName "Hanzo Hasashi" -Surname "Hasashi" -GivenName "Hanzo" -PasswordNeverExpires $true -UserPrincipalName "scorpion@yp-lab.edu" -Description "Cloud owner" -ErrorAction SilentlyContinue
New-ADUser -Name "Kuai Liang" -Accountpassword $SecurePassword -Enabled $true -Path "OU=Org, $DomainDN" -SamAccountName "sub-zero" -DisplayName "Kuai Liang" -Surname "Liang" -GivenName "Kuai" -PasswordNeverExpires $true -UserPrincipalName "sub-zero@yp-lab.edu" -Description "System administrator" -ErrorAction SilentlyContinue

<#
Start-BitsTransfer -Source "https://storage.yandexcloud.net/securitylab/RootCA.cer" -Destination "C:\Stages"
Start-BitsTransfer -Source "https://storage.yandexcloud.net/securitylab/SubCA.cer" -Destination "C:\Stages"
Start-BitsTransfer -Source "https://storage.yandexcloud.net/securitylab/adfs.pfx" -Destination "C:\Stages"
Start-BitsTransfer -Source "https://storage.yandexcloud.net/securitylab/SubCA.crl" -Destination "C:\Stages"
Start-BitsTransfer -Source "https://storage.yandexcloud.net/securitylab/SubCA+.crl" -Destination "C:\Stages"
#>
Start-Sleep 1
Import-Certificate -FilePath C:\Stages\RootCA.cer -CertStoreLocation Cert:\LocalMachine\Root\
Import-Certificate -FilePath C:\Stages\SubCA.cer -CertStoreLocation Cert:\LocalMachine\CA\
Import-PfxCertificate -FilePath C:\Stages\adfs.pfx -CertStoreLocation Cert:\LocalMachine\My -Password $SecurePassword
certutil -addstore -f CA C:\Stages\SubCA.crl
certutil -addstore -f CA C:\Stages\SubCA+.crl

$IPAddress = Get-NetIPAddress -AddressFamily IPv4 | where {$_.InterfaceAlias -notlike "*Loopback*"}
Add-DnsServerResourceRecordA -Name "fs" -IPv4Address $IPAddress.IPAddress -ZoneName "yp-lab.edu"
Start-Sleep 1

Add-DnsServerForwarder -IPAddress 8.8.8.8
Add-DnsServerForwarder -IPAddress 8.8.4.4

$AdminPass = Get-Content "C:\Stages\passwd.txt"
$SecurePassword = ConvertTo-SecureString $AdminPass -AsPlainText -Force
[pscredential]$Cred = New-Object System.Management.Automation.PSCredential ("yp-lab\Administrator", $SecurePassword)

$Arguments = @($DomainDN)
$Job = Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $Cred -ArgumentList $Arguments -ScriptBlock {
    Param (
        $DomainDN
    )

    $Thumbprint = (Get-ChildItem Cert:\localmachine\My\ | where {$_.Subject -like "*fs.yp-lab.edu*"}).Thumbprint
    $ADFSName = "YP-LAB ADFS"
    $FSName = "fs.yp-lab.edu"

    $DomainName = (Get-ADDomain -Current LoggedOnUser).DNSRoot
    $LocalHostname = $env:ComputerName
    $FQDN = ([System.Net.Dns]::GetHostByName($env:computerName)).Hostname

    $ADServiceAccountName = "ADFSgMSAccount"
    $gMSAOU = "CN=Managed Service Accounts,$DomainDN"

    #Creating new group managed service account
    Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
    New-ADServiceAccount -Name $ADServiceAccountName -Enabled $true -Path $gMSAOU -DNSHostName $FSName -PrincipalsAllowedToRetrieveManagedPassword $LocalHostname"$"
    Add-ADComputerServiceAccount -Identity $LocalHostname -ServiceAccount $ADServiceAccountName
    #Setting KCD
    Get-ADObject -Filter {Name -eq "$LocalHostname" -and ObjectClass -eq "computer"} | Set-ADObject -Add @{"msDS-AllowedToDelegateTo" = @("HOST/$LocalHostname","HOST/$FQDN","rpcss/$LocalHostname","rpcss/$FQDN")}
    Get-ADObject -Filter {Name -eq "ADFSgMSAccount"} | Set-ADObject -Add @{"msDS-AllowedToDelegateTo" = @("HOST/$LocalHostname","HOST/$FQDN","rpcss/$LocalHostname","rpcss/$FQDN")}

    #Setting SPN to gMSA
    Get-ADObject -Filter {Name -eq "ADFSgMSAccount"} | Set-ADObject -Add @{"servicePrincipalName" = @("HTTP/$LocalHostname","HTTP/$FQDN","HTTP/$FSName")}
    Set-ADServiceAccount -Identity $ADServiceAccountName -TrustedForDelegation $true
    Install-ADServiceAccount -Identity ADFSgMSAccount

    # Installing and configuring ADDS
    $outNull = Install-WindowsFeature ADFS-Federation -IncludeAllSubFeature -IncludeManagementTools -Confirm:$false
    Install-AdfsFarm -CertificateThumbprint $Thumbprint -FederationServiceDisplayName $ADFSName -FederationServiceName $FSName -GroupServiceAccountIdentifier "yp-lab\ADFSgMSAccount$"
}

reg delete HKLM\System\CurrentControlSet\Services\StageService\Parameters\ /v Application /f
reg add HKLM\System\CurrentControlSet\Services\StageService\Parameters\ /v Application /t REG_SZ /d C:\Stages\StageService3.bat

shutdown -r -t 0
