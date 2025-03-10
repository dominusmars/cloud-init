function Find-FullPathInDrive {
    param (
        [string]$Drive,
        [string]$file
    )

    $isPath = $file -match "/"
    if ($isPath) {
        $file = $file.Split("/")[-1]
    }
    
    # Write-CloudLog "Searching for $file in $Drive" -Level "DEBUG"

    $file_path = Get-ChildItem -Path $Drive -Recurse -Filter $file | ForEach-Object { $_.FullName  }

    if ($file_path) {
        # Write-CloudLog "Found ${file} in ${Drive} at ${file_path}" -Level "INFO"
        return $file_path
    }
    else {
        # Write-CloudLog "No ${file} found" -Level "WARN"
        return $null
    }

    
}
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
function Get-CloudMetadata {
    param (
        [string]$CloudDrive
    )
    
    $metadataPath = Find-FullPathInDrive -Drive $CloudDrive -file $meta_data_label
    if (-not (Test-Path $metadataPath)) {
        # Write-CloudLog "No meta-data file found" -Level "WARN"
        return $null
    }
    
    try {
        $content = Get-Content $metadataPath -Raw
        # Write-CloudLog "Successfully read meta-data file" -Level "DEBUG"
        
        # Parse the metadata
        # Cloud-init metadata can be in YAML or JSON format
        if ($content -match "^---") {
            # Looks like YAML
            # Write-CloudLog "Detected YAML format meta-data" -Level "DEBUG"
            if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
                # Write-CloudLog "Installing PowerShell-Yaml module..." -Level "DEBUG"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
                Install-Module -Name powershell-yaml -Force -Scope CurrentUser | Out-Null
            }
            Import-Module powershell-yaml
            return ConvertFrom-Yaml $content
        }
        elseif ($content -match "^\s*{") {
            # Looks like JSON
            # Write-CloudLog "Detected JSON format meta-data" -Level "DEBUG"
            return $content | ConvertFrom-Json
        }
        else {
            # Assume simple key-value format
            # Write-CloudLog "Detected simple key-value format meta-data" -Level "DEBUG"
            $metadata = @{}
            foreach ($line in ($content -split "`n")) {
                if ($line -match "^([^:]+):\s*(.+)$") {
                    $metadata[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            return $metadata
        }
    }
    catch {
        # Write-CloudLog "Error reading meta-data: $_" -Level "ERROR"
        return $null
    }
}
$user_data_label = "USER_DATA"
$meta_data_label = "META_DATA.JSON"
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
        # Write-CloudLog "Successfully read user-data file" -Level "DEBUG"
        
        # Check for cloud-config format
        if ($content -match "^#cloud-config") {
            # Write-CloudLog "Detected cloud-config format user-data" -Level "DEBUG"
            
            # Remove the #cloud-config line
            $yamlContent = $content -replace "^#cloud-config\s*", ""
            
            # Parse YAML
            if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
                # Write-CloudLog "Installing PowerShell-Yaml module..." -Level "DEBUG"
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
        # Write-CloudLog "Error reading user-data: $_" -Level "ERROR"
        return $null
    }
}
function ConvertTo-GatewayLength{
    param (
        [string]$netmask
    )
    $octets = $netmask -split "\."
    $binary = ($octets | ForEach-Object { [Convert]::ToString([byte]$_, 2).PadLeft(8, '0') }) -join ""
    return ($binary -replace "0+$").Length
}


$networkConfigPath = "C:\Users\khawa\gits\cloud-init\testing\CONTENT\0000"

$networkDef = Get-Content $networkConfigPath -Raw

if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
    # Write-CloudLog "Installing PowerShell-Yaml module..." -Level "DEBUG"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Install-Module -Name powershell-yaml -Force -Scope CurrentUser | Out-Null
}
Import-Module powershell-yaml

$config = Convert-UnixStyleNetworkDef -networkDef $networkDef

Write-Host "Interface: $($config.interface)"
Write-Host "Inet: $($config.inet)"
Write-Host "Address: $($config.address)"
Write-Host "Netmask: $($config.netmask)"
Write-Host "Gateway: $($config.gateway)"
Write-Host "DNS: $($config.dns -join ", ")"

$userData = Get-CloudMetadata -CloudDrive "C:"

Write-Host "User Data: $($userData | ConvertTo-Json -Depth 5)"


