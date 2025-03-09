
function Convert-UnixStyleNetworkDef {
    param (
        [string]$networkDef
    )

    $lines = $networkDef -split "`n"
    $config = @{
        interface = ""
        inet = ""
        address = ""
        netmask = ""
        gateway = ""
        dns = @()
    }

    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -match "^auto\s+(\S+)") {
            $config.interface = $Matches[1]
        }
        elseif ($line -match "^iface\s+\S+\s+inet\s+(\S+)") {
            $config.inet = $Matches[1]
        }
        elseif ($line -match "^\s*address\s+(\S+)") {
            $config.address = $Matches[1]
        }
        elseif ($line -match "^\s*netmask\s+(\S+)") {
            $config.netmask = $Matches[1]
        }
        elseif ($line -match "^\s*gateway\s+(\S+)") {
            $config.gateway = $Matches[1]
        }
        elseif ($line -match "^\s*dns-nameservers\s+(.+)$") {
            $config.dns = $Matches[1] -split "\s+"
        }
    }

    return $config

}
function Get-CloudUserdata {
    param (
        [string]$CloudDrive
    )
    
    $userdataPath = Find-FullPathInDrive $CloudDrive $user_data_label
    if (-not (Test-Path $userdataPath)) {
        Write-CloudLog "No user-data file found" -Level "WARN"
        return $null
    }
    
    try {
        $content = Get-Content $userdataPath -Raw
        Write-CloudLog "Successfully read user-data file" -Level "DEBUG"
        
        # Check for cloud-config format
        if ($content -match "^#cloud-config") {
            Write-CloudLog "Detected cloud-config format user-data" -Level "DEBUG"
            
            # Remove the #cloud-config line
            $yamlContent = $content -replace "^#cloud-config\s*", ""
            
            # Parse YAML
            if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
                Write-CloudLog "Installing PowerShell-Yaml module..." -Level "DEBUG"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
                Install-Module -Name powershell-yaml -Force -Scope CurrentUser | Out-Null
            }
            Import-Module powershell-yaml
            return ConvertFrom-Yaml $yamlContent
        }
        else {
            # Return raw content for script or other formats
            return @{
                "content" = $content
                "format" = if ($content -match "^#!ps1|^<powershell>") { "powershell" } 
                           elseif ($content -match "^#!cmd|^<script>") { "cmd" } 
                           else { "unknown" }
            }
        }
    }
    catch {
        Write-CloudLog "Error reading user-data: $_" -Level "ERROR"
        return $null
    }
}



$networkDef = @"
auto eth0
iface eth0 inet dhcp
    address 192.168.32.11
    netmask 255.255.255.0
    gateway 192.168.32.1
    dns-nameservers 121.1.1.1 1.1.1.1
"@

if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
    # Write-CloudLog "Installing PowerShell-Yaml module..." -Level "DEBUG"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Install-Module -Name powershell-yaml -Force -Scope CurrentUser | Out-Null
}
Import-Module powershell-yaml
Write-Host (Get-Content "./testing/LATEST/META_DATA.JSON" | ConvertFrom-Json | ConvertTo-Yaml)
Write-Host (Get-Content "./testing/LATEST/USER_DATA" | ConvertFrom-Yaml | ConvertTo-Yaml)

