If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

Set-ExecutionPolicy Unrestricted

certutil -addstore "TrustedPublisher" D:\redhat1.cer | Out-Null
certutil -addstore "TrustedPublisher" D:\redhat2.cer | Out-Null

msiexec /i "E:\virtio-win-gt-x64.msi" /qn /passive | Out-Null
Start-Sleep -s 4
$url = "https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe"
$output = "C:\Users/VM/Downloads\spice-guest-tools-latest.exe"
Invoke-WebRequest -Uri $url -OutFile $output
& "C:\Users\VM\Downloads\spice-guest-tools-latest.exe" /S | Out-Null
& "C:\Users\VM\Downloads\spice-guest-tools-latest.exe" /S | Out-Null

dism /Online /Add-Capability /CapabilityName:Windows.Desktop.EMS-SAC.Tools~~~~0.0.1.0 /NoRestart
bcdedit /emssettings EMSPORT:1 EMSBAUDRATE:115200
bcdedit /ems ON

$ip = (cat D:\sambainfo.txt)[0]
$user = (cat D:\sambainfo.txt)[1]
$pass = (cat D:\sambainfo.txt)[2]
cmdkey /add:$ip /user:$user /pass:$pass

$url = "https://raw.githubusercontent.com/cbaldan/Debloat-Windows-10/master/scripts/7.unbloat-start-menu.ps1"
$output = "Users\VM\Documents\unpin.ps1"
Invoke-WebRequest -Uri $url -OutFile $output
& "C:\Users\VM\Documents\unpin.ps1"

$url = "https://raw.githubusercontent.com/vlinkz/WinminWindows/master/startps.bat"
$output = "C:\Windows\system32\startps.bat"
Invoke-WebRequest -Uri $url -OutFile $output

$url = "https://raw.githubusercontent.com/vlinkz/Windows10Debloater/master/Windows10SysPrepDebloater.ps1"
$output = "C:\Users\VM\Documents\Windows10SysPrepDebloater.ps1"
Invoke-WebRequest -Uri $url -OutFile $output
& "C:\Users\VM\Documents\Windows10SysPrepDebloater.ps1"

$url = "https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/scripts/disable-windows-defender.ps1"
$output = "C:\Users\VM\Documents\disable-windows-defender.ps1"
Invoke-WebRequest -Uri $url -OutFile $output
& "C:\Users\VM\Documents\disable-windows-defender.ps1"

$url = "https://raw.githubusercontent.com/vlinkz/WinminWindows/master/features.bat"
$output = "C:\Users\VM\Documents\features.bat"
Invoke-WebRequest -Uri $url -OutFile $output
& "C:\Users\VM\Documents\features.bat"

$url = "https://raw.githubusercontent.com/vlinkz/WinminWindows/master/power.bat"
$output = "C:\Users\VM\Documents\power.bat"
Invoke-WebRequest -Uri $url -OutFile $output
& "C:\Users\VM\Documents\power.bat"

$url = "https://raw.githubusercontent.com/vlinkz/WinminWindows/master/disable-services.ps1"
$output = "C:\Users\VM\Documents\disable-services.ps1"
Invoke-WebRequest -Uri $url -OutFile $output
& "C:\Users\VM\Documents\disable-services.ps1"


setx /M path "$env:PATH;C:\ProgramData\Microsoft\Windows\Start Menu\Programs"

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon"

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "VM"  -PropertyType "String"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value "vm"  -PropertyType "String"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1"  -PropertyType "String"

reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v WallPaper /t REG_SZ /d " " /f
reg add "HKEY_CURRENT_USER\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarSmallIcons /t REG_DWORD /d "1" /f

$p='HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
$v=(Get-ItemProperty -Path $p).Settings
$v[8]=3
Set-ItemProperty -Path $p -Name Settings -Value $v

$url = "https://raw.githubusercontent.com/vlinkz/WinminWindows/master/ooshutup10.cfg"
$output = "C:\Users\VM\Documents\ooshutup10.cfg"
Invoke-WebRequest -Uri $url -OutFile $output

$url = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
$output = "C:\Users\VM\Documents\OOSU10.exe"
Invoke-WebRequest -Uri $url -OutFile $output

& "C:\Users\VM\Documents\OOSU10.exe" "C:\Users\VM\Documents\ooshutup10.cfg" /nosrp /quiet

Stop-Process -f -ProcessName explorer

schtasks /create /tn "shutdown2" /sc onlogon /tr "cmd.exe /c schtasks /delete /tn shutdown2 /F && shutdown -s -t 0"

Restart-Computer
