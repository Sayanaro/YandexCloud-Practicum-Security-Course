reg delete HKLM\SYSTEM\CurrentControlSet\Services\StageService /f
sc delete StageService
taskkill /im srvany.exe /f
Remove-Item -Path C:\Stages -Recurse -Force
