
# Make sure to run this script as Administrator

$logDir = "C:\cloudbase-init\logs"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

Copy-Item -Path "./cloud-init.ps1" -Destination "C:\cloudbase-init\" -Force
Copy-Item -Path "./start.bat" -Destination "C:\cloudbase-init\" -Force

sc.exe create cloudbase-init binPath= "C:\cloudbase-init\start.bat" start= auto
Start-Service cloudbase-init
