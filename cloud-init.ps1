# Windows-CloudInit-Processor.ps1
# Script to read cloud-init drive and configure Windows system
# Save this as a startup script for your Windows image

# Enable verbose logging
$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"

# Log file location
$logDir = "C:\cloudbase-init\logs"
$logFile = "$logDir\cloudbase-init-custom.log"

$meta_data_label ="META_DATA.JSON"
$user_data_label = "USER_DATA"


# Ensure log directory exists
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Function to write to log file
function Write-CloudLog {
    param (
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logMessage -Force
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARN"  { Write-Warning $Message }
        "DEBUG" { Write-Verbose $Message }
        default { Write-Host $Message }
    }
}

Write-CloudLog "Starting cloud-init processing for Windows..."

# Function to find the cloud-init drive
function Find-CloudInitDrive {
    Write-CloudLog "Searching for cloud-init data drive..." -Level "DEBUG"
    
    # Check for drive labels commonly used for cloud-init
    $cloudDrives = Get-Volume | Where-Object { 
        $_.FileSystemLabel -match "cidata|config-2" -or
        $_.DriveType -eq 5  # CD-ROM drives
    }

    
    foreach ($drive in $cloudDrives) {
        $driveLetter = $drive.DriveLetter
        $drivePath = "${driveLetter}:\"

        Write-CloudLog "Checking drive $drivePath" -Level "DEBUG"
        
        # Search recursively for cloud-init specific files
        $cloudMetaData = Get-ChildItem -Path $drivePath -Recurse -Filter $meta_data_label
        $cloudUserFile = Get-ChildItem -Path $drivePath -Recurse -Filter $user_data_label
        
        if (-not $cloudMetaData -or -not $cloudUserFile) {
            Write-CloudLog "No cloud-init files found in ${drivePath}" -Level "DEBUG"
            continue
        }

        Write-CloudLog "Found cloud-init files in ${drivePath}" -Level "INFO"
        return $drivePath
       
    }
    
    # Check all drives as a fallback
   
    Write-CloudLog "No cloud-init drive found" -Level "WARN"
    return $null
}

# Function to find the full path of a file in a drive
# If the file is in a subdirectory, only the filename is provided
# else will split the path and get the last element
function Find-FullPathInDrive {
    param (
        [string]$Drive,
        [string]$file
    )

    $isPath = $file -match "/"
    if ($isPath) {
        $file = $file.Split("/")[-1]
    }
    
    Write-CloudLog "Searching for $file in $Drive" -Level "DEBUG"

    $file_path = Get-ChildItem -Path $Drive -Recurse -Filter $file | ForEach-Object { $_.FullName  }

    if ($file_path) {
        Write-CloudLog "Found ${file} in ${Drive} at ${file_path}" -Level "INFO"
        return $file_path
    }
    else {
        Write-CloudLog "No ${file} found" -Level "WARN"
        return $null
    }

    
}

# Function to read cloud-init metadata
function Get-CloudMetadata {
    param (
        [string]$CloudDrive
    )
    
    $metadataPath = Find-FullPathInDrive -Drive $CloudDrive -file $meta_data_label
    if (-not (Test-Path $metadataPath)) {
        Write-CloudLog "No meta-data file found" -Level "WARN"
        return $null
    }
    
    try {
        $content = Get-Content $metadataPath -Raw
        Write-CloudLog "Successfully read meta-data file" -Level "DEBUG"
        
        # Parse the metadata
        # Cloud-init metadata can be in YAML or JSON format
        if ($content -match "^---") {
            # Looks like YAML
            Write-CloudLog "Detected YAML format meta-data" -Level "DEBUG"
            if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
                Write-CloudLog "Installing PowerShell-Yaml module..." -Level "DEBUG"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
                Install-Module -Name powershell-yaml -Force -Scope CurrentUser | Out-Null
            }
            Import-Module powershell-yaml
            return ConvertFrom-Yaml $content
        }
        elseif ($content -match "^\s*{") {
            # Looks like JSON
            Write-CloudLog "Detected JSON format meta-data" -Level "DEBUG"
            return $content | ConvertFrom-Json
        }
        else {
            # Assume simple key-value format
            Write-CloudLog "Detected simple key-value format meta-data" -Level "DEBUG"
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
        Write-CloudLog "Error reading meta-data: $_" -Level "ERROR"
        return $null
    }
}

# Function to read cloud-init userdata
function Get-CloudUserdata {
    param (
        [string]$CloudDrive
    )
    
    $userdataPath = Find-FullPathInDrive -Drive $CloudDrive -file $user_data_label
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
function ConvertTo-GatewayLength{
    param (
        [string]$netmask
    )
    $octets = $netmask -split "\."
    $binary = ($octets | ForEach-Object { [Convert]::ToString([byte]$_, 2).PadLeft(8, '0') }) -join ""
    return ($binary -replace "0+$").Length
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
    Write-Host $networkDef

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
            $match = $Matches[1]
            if ($match -match "\d+\.\d+\.\d+\.\d+") {
                $config.netmask = ConvertTo-GatewayLength -netmask $match
            }else{
                $config.netmask = $match
            }
        }
        elseif ($line -match "^\s*gateway\s+(\S+)") {
            $config.gateway = $Matches[1]
        }
        elseif ($line -match "^\s*dns-nameservers\s+(.+)$") {
            $config.dns = $Matches[1] -split "\s+"
        }
    }
    Write-Host "Interface: $($config.interface)"
    Write-Host "Inet: $($config.inet)"
    Write-Host "Address: $($config.address)"
    Write-Host "Netmask: $($config.netmask)"
    Write-Host "Gateway: $($config.gateway)"
    Write-Host "DNS: $($config.dns -join ', ')"

    return $config

}

# Function to read network configuration
function Get-CloudNetworkConfig {
    param (
        [string]$CloudDrive,
        [string]$NetworkConfigPath
    )
    
    $networkConfigPath = Find-FullPathInDrive -Drive $CloudDrive -file $NetworkConfigPath
    if (-not (Test-Path $networkConfigPath)) {
        Write-CloudLog "No network-config file found" -Level "WARN"
        return $null
    }
    
    try {
        $content = Get-Content $networkConfigPath -Raw
        Write-CloudLog "Successfully read network-config file" -Level "DEBUG"
        

        if ($content -match "^auto\s+(\S+)") {
            Write-CloudLog "Detected Unix-style network configuration" -Level "DEBUG"
            return Convert-UnixStyleNetworkDef $content
        }

        # Parse YAML network config
        if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
            Write-CloudLog "Installing PowerShell-Yaml module..." -Level "DEBUG"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
            Install-Module -Name powershell-yaml -Force -Scope CurrentUser | Out-Null
        }
        Import-Module powershell-yaml
        return ConvertFrom-Yaml $content
    }
    catch {
        Write-CloudLog "Error reading network-config: $_" -Level "ERROR"
        return $null
    }
}

# Function to apply metadata configuration
# sets the administrator password and SSH public keys and network configuration
function Set-MetadataConfig {
    param (
        [object]$Metadata
    )
    
    if (-not $Metadata) {
        Write-CloudLog "No metadata to apply" -Level "DEBUG"
        return
    }
    
    Write-CloudLog "Applying metadata configuration..." -Level "INFO"


    if ($Metadata.admin_pass) {
        Write-CloudLog "Setting administrator password" -Level "INFO"
        $securePassword = ConvertTo-SecureString -String $Metadata.admin_pass -AsPlainText -Force
        $adminUser = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if (-not $adminUser) {
            Write-CloudLog "Creating Administrator user" -Level "INFO"
            New-LocalUser -Name "Administrator" -Password $securePassword -Description "Created by cloud-init" -ErrorAction Stop
        }
        else {
            Write-CloudLog "Setting password for Administrator user" -Level "INFO"
            $adminUser | Set-LocalUser -Password $securePassword -ErrorAction Stop
        }
    }
    
    # Public keys
    if ($Metadata.public_keys) {
        Set-SSHPublicKeys -PublicKeys $Metadata.public_keys
    }

    # Network configuration
    if ($Metadata.network_config) {
        $networkConfig =  Get-CloudNetworkConfig $CloudDrive $Metadata.network_config.content_path
        Set-CloudNetworkConfig -NetworkConfig $networkConfig
    }

}

# Function to apply SSH public keys
function Set-SSHPublicKeys {
    param (
        [object]$PublicKeys
    )
    
    Write-CloudLog "Processing SSH public keys..." -Level "INFO"
    
    # Create .ssh directory if it doesn't exist
    $sshDir = "$env:USERPROFILE\.ssh"
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    }
    
    $authorizedKeysPath = "$sshDir\authorized_keys"
    
    # Process keys based on format
    if ($PublicKeys -is [System.Collections.IDictionary]) {
        # Handle dictionary of keys
        foreach ($keyName in $PublicKeys.Keys) {
            $keyValue = $PublicKeys[$keyName]
            Write-CloudLog "Adding SSH key: $keyName" -Level "DEBUG"
            Add-Content -Path $authorizedKeysPath -Value $keyValue -Force
        }
    }
    elseif ($PublicKeys -is [System.Array]) {
        # Handle array of keys
        foreach ($key in $PublicKeys) {
            Write-CloudLog "Adding SSH key" -Level "DEBUG"
            Add-Content -Path $authorizedKeysPath -Value $key -Force
        }
    }
    elseif ($PublicKeys -is [System.String]) {
        # Handle single key as string
        Write-CloudLog "Adding SSH key" -Level "DEBUG"
        Add-Content -Path $authorizedKeysPath -Value $PublicKeys -Force
    }
    else {
        Write-CloudLog "Invalid SSH public keys format" -Level "WARN"
    }
    
    Write-CloudLog "SSH public keys processed" -Level "INFO"
}

# Function to apply network configuration
function Set-CloudNetworkConfig {
    param (
        [System.Object]$NetworkConfig
    )
    
    if (-not $NetworkConfig) {
        Write-CloudLog "No network configuration to apply" -Level "DEBUG"
        return
    }
    
    Write-CloudLog "Applying network configuration..." -Level "INFO"


    try {
        # Get network adapters
        $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        if (-not $netAdapters) {
            Write-CloudLog "No active network adapters found" -Level "WARN"
            return
        }
        $adapter = $netAdapters | Select-Object -First 1

        if($NetworkConfig.interface) {
            # Unix-style network configuration

            if ($NetworkConfig.inet -eq "dhcp") {
                Write-CloudLog "Setting adapter to use DHCP" -Level "INFO"
                Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Dhcp Enabled
            }elseif($NetworkConfig.inet -eq "static") {
                $ipAddress = $NetworkConfig.address
                $prefixLength = $NetworkConfig.netmask
                Write-CloudLog "Setting static IP: $ipAddress/$prefixLength" -Level "INFO"
                Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
                # might need to convert to number
                New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $ipAddress -PrefixLength $prefixLength
    
                # Set gateway if provided
                if ($NetworkConfig.gateway) {
                    Write-CloudLog "Setting gateway: $($NetworkConfig.gateway)" -Level "INFO"
                    Remove-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
                    New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -NextHop $NetworkConfig.gateway
                }
            }

          
            # Set DNS servers
            if ($NetworkConfig.dns) {
                $dnsServers = $NetworkConfig.dns
                Write-CloudLog "Setting DNS servers: $($dnsServers -join ', ')" -Level "INFO"
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServers
            }

            return 
        }

        
        # Process network config format
        if ($NetworkConfig.version -eq 1) {
            # Version 1 format
            if ($NetworkConfig.config) {
                foreach ($config in $NetworkConfig.config) {
                    if ($config.type -eq "physical") {
                        $adapter = $netAdapters | Select-Object -First 1
                        
                        if ($config.subnets) {
                            foreach ($subnet in $config.subnets) {
                                # Handle static IP
                                if ($subnet.type -eq "static") {
                                    $ipAddress = $subnet.address
                                    $prefixLength = $subnet.netmask
                                    
                                    # Convert netmask to prefix length if needed
                                    if ($prefixLength -match "\d+\.\d+\.\d+\.\d+") {
                                        $octets = $prefixLength -split "\."
                                        $binary = ($octets | ForEach-Object { [Convert]::ToString([byte]$_, 2).PadLeft(8, '0') }) -join ""
                                        $prefixLength = ($binary -replace "0+$").Length
                                    }
                                    
                                    Write-CloudLog "Setting static IP: $ipAddress/$prefixLength" -Level "INFO"
                                    Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
                                    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $ipAddress -PrefixLength $prefixLength
                                    
                                    # Set gateway if provided
                                    if ($subnet.gateway) {
                                        Write-CloudLog "Setting gateway: $($subnet.gateway)" -Level "INFO"
                                        Remove-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
                                        New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -NextHop $subnet.gateway
                                    }
                                }
                                elseif ($subnet.type -eq "dhcp") {
                                    Write-CloudLog "Setting adapter to use DHCP" -Level "INFO"
                                    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Dhcp Enabled
                                }
                            }
                        }
                    }
                }
            }
        }
        elseif ($NetworkConfig.version -eq 2) {
            # Version 2 format
            if ($NetworkConfig.ethernets) {
                $ethernetConfig = $NetworkConfig.ethernets | Select-Object -First 1
                $adapter = $netAdapters | Select-Object -First 1
                
                if ($ethernetConfig.Value.dhcp4) {
                    Write-CloudLog "Setting adapter to use DHCP" -Level "INFO"
                    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Dhcp Enabled
                }
                elseif ($ethernetConfig.Value.addresses) {
                    foreach ($address in $ethernetConfig.Value.addresses) {
                        # Parse CIDR notation (e.g., "192.168.1.10/24")
                        if ($address -match "^(.+)/(\d+)$") {
                            $ipAddress = $Matches[1]
                            $prefixLength = $Matches[2]
                            
                            Write-CloudLog "Setting static IP: $ipAddress/$prefixLength" -Level "INFO"
                            Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
                            New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $ipAddress -PrefixLength $prefixLength
                        }
                    }
                    
                    # Set gateway
                    if ($ethernetConfig.Value.gateway4) {
                        Write-CloudLog "Setting gateway: $($ethernetConfig.Value.gateway4)" -Level "INFO"
                        Remove-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
                        New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -NextHop $ethernetConfig.Value.gateway4
                    }
                }
                
                # Set DNS servers
                if ($ethernetConfig.Value.nameservers -and $ethernetConfig.Value.nameservers.addresses) {
                    $dnsServers = $ethernetConfig.Value.nameservers.addresses
                    Write-CloudLog "Setting DNS servers: $($dnsServers -join ', ')" -Level "INFO"
                    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServers
                }
            }
        }
    }
    catch {
        Write-CloudLog "Error applying network configuration: $_" -Level "ERROR"
    }
}

# Function to apply user-data configuration
function Set-CloudUserdata {
    param (
        [object]$Userdata
    )
    
    if (-not $Userdata) {
        Write-CloudLog "No user-data to apply" -Level "DEBUG"
        return
    }
    
    Write-CloudLog "Applying user-data configuration..." -Level "INFO"
    
    # Check if it's cloud-config YAML format
    if ($Userdata -is [System.Collections.IDictionary]) {
        # Set hostname
        if ($Userdata.hostname) {
            Write-CloudLog "Setting hostname to: $($Userdata.hostname)" -Level "INFO"
            try {
                Rename-Computer -NewName $Userdata.hostname -Force -ErrorAction Continue
                Write-CloudLog "Hostname set successfully, reboot required to apply" -Level "INFO"
                $script:rebootRequired = $true
            }
            catch {
                Write-CloudLog "Error setting hostname: $_" -Level "ERROR"
            }
        }
        if ($Userdata.fqdn) {
            Write-CloudLog "Setting FQDN to: $($Userdata.fqdn)" -Level "INFO"
            try {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "NV Domain" -Value $Userdata.fqdn -ErrorAction Continue
            }
            catch {
                Write-CloudLog "Error setting FQDN: $_" -Level "ERROR"
            }
        }
        
        # Create users
        if ($Userdata.users) {
            foreach ($user in $Userdata.users) {
                if ($user -eq "default") { continue }
                
                Write-CloudLog "Creating user: $($user.name)" -Level "INFO"
                
                try {
                    $userParams = @{
                        Name = $user.name
                    }
                    
                    # Set password if provided
                    if ($user.passwd) {
                        $securePassword = ConvertTo-SecureString -String $user.passwd -AsPlainText -Force
                        $userParams.Password = $securePassword
                    }
                    
                    # Set full name if provided
                    if ($user.gecos) {
                        $userParams.FullName = $user.gecos
                    }
                    
                    # Create the user
                    New-LocalUser @userParams -Description "Created by cloud-init" -ErrorAction Stop
                    
                    # Add to groups
                    if ($user.groups) {
                        foreach ($groupName in $user.groups.Split(',')) {
                            $groupName = $groupName.Trim()
                            
                            # Map common Linux group names to Windows equivalents
                            switch ($groupName) {
                                "sudo" { $groupName = "Administrators" }
                                "wheel" { $groupName = "Administrators" }
                                "root" { $groupName = "Administrators" }
                                default { }
                            }
                            
                            # Create the group if it doesn't exist (except built-in groups)
                            if ($groupName -notin @("Administrators", "Users")) {
                                if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
                                    New-LocalGroup -Name $groupName -ErrorAction SilentlyContinue
                                }
                            }
                            
                            # Add user to group
                            Add-LocalGroupMember -Group $groupName -Member $user.name -ErrorAction SilentlyContinue
                        }
                    }
                    
                    # Handle SSH keys
                    if ($user.ssh_authorized_keys) {
                        $sshDir = "C:\Users\$($user.name)\.ssh"
                        if (-not (Test-Path $sshDir)) {
                            New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
                        }
                        
                        $authorizedKeysPath = "$sshDir\authorized_keys"
                        
                        foreach ($key in $user.ssh_authorized_keys) {
                            Add-Content -Path $authorizedKeysPath -Value $key -Force
                        }
                    }
                }
                catch {
                    Write-CloudLog "Error creating user $($user.name): $_" -Level "ERROR"
                }
            }
        }
        
        # Run commands
        if ($Userdata.runcmd) {
            Write-CloudLog "Processing run commands..." -Level "INFO"
            
            foreach ($cmd in $Userdata.runcmd) {
                try {
                    if ($cmd -is [System.Array]) {
                        $command = $cmd -join " "
                    }
                    else {
                        $command = $cmd
                    }
                    
                    Write-CloudLog "Running command: $command" -Level "INFO"
                    
                    # Execute the command based on its format
                    if ($command.StartsWith("powershell") -or $command.StartsWith("pwsh")) {
                        $psCommand = $command -replace "^powershell\s+", "" -replace "^pwsh\s+", ""
                        $scriptBlock = [ScriptBlock]::Create($psCommand)
                        & $scriptBlock
                    }
                    else {
                        Start-Process "cmd.exe" -ArgumentList "/c $command" -Wait -NoNewWindow
                    }
                }
                catch {
                    Write-CloudLog "Error running command '$command': $_" -Level "ERROR"
                }
            }
        }
        
        # Write files
        if ($Userdata.write_files) {
            Write-CloudLog "Processing write_files section..." -Level "INFO"
            
            foreach ($file in $Userdata.write_files) {
                try {
                    $filePath = $file.path
                    $content = $file.content
                    
                    Write-CloudLog "Writing file: $filePath" -Level "INFO"
                    
                    # Create directory if it doesn't exist
                    $directory = Split-Path -Path $filePath -Parent
                    if (-not (Test-Path $directory)) {
                        New-Item -ItemType Directory -Path $directory -Force | Out-Null
                    }
                    
                    # Handle encoding
                    if ($file.encoding -eq "base64") {
                        $bytes = [Convert]::FromBase64String($content)
                        [System.IO.File]::WriteAllBytes($filePath, $bytes)
                    }
                    else {
                        Set-Content -Path $filePath -Value $content -Force
                    }
                }
                catch {
                    Write-CloudLog "Error writing file $filePath $_" -Level "ERROR"
                }
            }
        }
        
        # Handle package installations
        if ($Userdata.packages) {
            Write-CloudLog "Processing packages section..." -Level "INFO"
            
            # Check if Chocolatey is installed
            $chocoInstalled = $null -ne (Get-Command -Name "choco" -ErrorAction SilentlyContinue)
            
            if (-not $chocoInstalled) {
                Write-CloudLog "Installing Chocolatey package manager..." -Level "INFO"
                try {
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                    $chocoInstalled = $true
                    
                    # Refresh environment to find choco in path
                    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                }
                catch {
                    Write-CloudLog "Error installing Chocolatey: $_" -Level "ERROR"
                }
            }
            
            if ($chocoInstalled) {
                foreach ($package in $Userdata.packages) {
                    try {
                        Write-CloudLog "Installing package: $package" -Level "INFO"
                        Start-Process -FilePath "choco" -ArgumentList "install $package -y" -Wait -NoNewWindow
                    }
                    catch {
                        Write-CloudLog "Error installing package $package $_" -Level "ERROR"
                    }
                }
            }
        }
    }
    # Check if it's a script format
    elseif ($Userdata.format -eq "powershell") {
        Write-CloudLog "Executing PowerShell script from user-data..." -Level "INFO"
        
        try {
            $scriptContent = $Userdata.content -replace "^#!ps1\s*", "" -replace "^<powershell>", "" -replace "</powershell>$", ""
            $scriptPath = "$logDir\user-data-script.ps1"
            
            Set-Content -Path $scriptPath -Value $scriptContent -Force
            
            # Execute the script
            & $scriptPath
        }
        catch {
            Write-CloudLog "Error executing PowerShell script: $_" -Level "ERROR"
        }
    }
    elseif ($Userdata.format -eq "cmd") {
        Write-CloudLog "Executing CMD script from user-data..." -Level "INFO"
        
        try {
            $scriptContent = $Userdata.content -replace "^#!cmd\s*", "" -replace "^<script>", "" -replace "</script>$", ""
            $scriptPath = "$logDir\user-data-script.cmd"
            
            Set-Content -Path $scriptPath -Value $scriptContent -Force
            
            # Execute the script
            Start-Process -FilePath $scriptPath -Wait -NoNewWindow
        }
        catch {
            Write-CloudLog "Error executing CMD script: $_" -Level "ERROR"
        }
    }
}

# Function to mark first boot as complete
function Set-FirstBootComplete {
    $markerFile = "$logDir\first-boot-complete"
    Set-Content -Path $markerFile -Value (Get-Date) -Force
    Write-CloudLog "First boot configuration completed" -Level "INFO"
}

# Main execution
try {
    # Check if this is first boot
    $markerFile = "$logDir\first-boot-complete"
    if (Test-Path $markerFile) {
        $completedTime = Get-Content $markerFile
        Write-CloudLog "First boot already completed on $completedTime. Exiting." -Level "INFO"
        exit 0
    }
    
    # Find cloud-init drive
    $cloudDrive = Find-CloudInitDrive
    if (-not $cloudDrive) {
        Write-CloudLog "No cloud-init drive found. Exiting." -Level "WARN"
        exit 0
    }
    
    # Variable to track if reboot is needed
    $script:rebootRequired = $false
    
    # Read cloud-init files
    $metadata = Get-CloudMetadata -CloudDrive $cloudDrive
    $userdata = Get-CloudUserdata -CloudDrive $cloudDrive
    
    # Apply configurations

    # also applies network configuration
    Set-MetadataConfig -Metadata $metadata 
    Set-CloudUserdata -Userdata $userdata

    
    # Mark first boot as complete
    Set-FirstBootComplete
    
    # Reboot if needed
    if ($script:rebootRequired) {
        Write-CloudLog "Configuration requires a reboot. Rebooting system..." -Level "INFO"
        Restart-Computer -Force
    }
    
    Write-CloudLog "Cloud-init processing completed successfully" -Level "INFO"
}
catch {
    Write-CloudLog "Unhandled exception in cloud-init processing: $_" -Level "ERROR"
    exit 1
}