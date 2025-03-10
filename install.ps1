
# Make sure to run this script as Administrator

$logDir = "C:\cloud-init\logs"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

Copy-Item -Path "./cloud-init.ps1" -Destination "C:\cloud-init\" -Force
Copy-Item -Path "./start.bat" -Destination "C:\cloud-init\" -Force

sc.exe create cloud-init binPath= "C:\cloud-init\start.bat" start= auto
Start-Service cloud-init
