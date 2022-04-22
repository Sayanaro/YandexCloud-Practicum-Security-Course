Start-Transcript -Path "$ENV:SystemDrive\Stage2.txt" -IncludeInvocationHeader -Force
$DSRMPassword = "!Q2w3e4r"
$DomanName = "yp-lab.edu"

# Installing and configuring ADDS
$outNull = Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools -Confirm:$false
$DSRM = ConvertTo-SecureString "$DSRMPassword" -AsPlainText -Force
reg delete HKLM\System\CurrentControlSet\Services\StageService\Parameters\ /v Application /f
reg add HKLM\System\CurrentControlSet\Services\StageService\Parameters\ /v Application /t REG_SZ /d C:\Stages\StageService3.bat
$outNull = Install-ADDSForest -DomainName $DomanName -InstallDNS -SafeModeAdministratorPassword $DSRM -DomainMode Default -DomainNetbiosName $DomanName.Substring(0, $DomanName.IndexOf('.')) -ForestMode Default -Confirm:$false -Force