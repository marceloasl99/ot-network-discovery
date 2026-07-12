#requires -Version 5.1
<#
.SYNOPSIS
    Discovers IPv4 neighbors on an authorized Windows network.
.DESCRIPTION
    Selects an active IPv4 interface, calculates the CIDR range, optionally
    performs bounded ICMP discovery, reads the Windows neighbor cache, and
    exports CSV, JSON, summary, and log files.
.NOTES
    Use only on networks you own or are explicitly authorized to assess.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("OT_Discovery_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [ValidateRange(100,5000)][int]$TimeoutMs = 450,
    [ValidateRange(1,128)][int]$ThrottleLimit = 32,
    [ValidateRange(1,4096)][int]$MaxHosts = 1024,
    [switch]$SkipActiveDiscovery,
    [switch]$IncludeAllNeighborStates,
    [switch]$ResolveDns,
    [switch]$IncludeLocalAddress,
    [string]$InterfaceAlias
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:LogFile = $null
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'

function Write-DiscoveryLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function Convert-IPv4ToUInt32 {
    param([Parameter(Mandatory=$true)][string]$Address)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) { throw "Invalid IPv4 address: $Address" }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw "Address is not IPv4: $Address" }
    $bytes = $parsed.GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Convert-UInt32ToIPv4 {
    param([Parameter(Mandatory=$true)][uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return (New-Object System.Net.IPAddress -ArgumentList (, $bytes)).IPAddressToString
}

function Get-SubnetInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 32)]
        [int]$PrefixLength
    )

    $ipValue = Convert-IPv4ToUInt32 -Address $Address
    

    # Não utilizar 0xFFFFFFFF no Windows PowerShell 5.1.
    # O PowerShell pode interpretar o literal hexadecimal como Int32 -1.
    $allBits = [uint64]4294967295

    if ($PrefixLength -eq 0) {
        $maskValue = [uint64]0
    }
    else {
        $hostBits = 32 - $PrefixLength

        $maskValue = ($allBits -shl $hostBits -band $allBits
        )
    }

    $inverseMask = $allBits -bxor $maskValue
    

    $networkValue = $ipValue -band $maskValue
    

    $broadcastValue = $networkValue -bor $inverseMask
    

    if ($PrefixLength -eq 32) {
        $firstHostValue = $networkValue
        $lastHostValue = $networkValue
        $usableHostCount = [uint64]1
    }
    elseif ($PrefixLength -eq 31) {
        # Redes /31 são válidas para enlaces ponto a ponto.
        $firstHostValue = $networkValue
        $lastHostValue = $broadcastValue
        $usableHostCount = [uint64]2
    }
    else {
        $firstHostValue = $networkValue + 1
        $lastHostValue = $broadcastValue - 1

        $usableHostCount = $broadcastValue -
            $networkValue -
            1
        
    }

    return [pscustomobject][ordered]@{
        NetworkAddress = Convert-UInt32ToIPv4 `
            -Value ([uint32]$networkValue)

        BroadcastAddress = Convert-UInt32ToIPv4 `
            -Value ([uint32]$broadcastValue)

        FirstHostAddress = Convert-UInt32ToIPv4 `
            -Value ([uint32]$firstHostValue)

        LastHostAddress = Convert-UInt32ToIPv4 `
            -Value ([uint32]$lastHostValue)

        PrefixLength = $PrefixLength

        MaskAddress = Convert-UInt32ToIPv4 `
            -Value ([uint32]$maskValue)

        NetworkValue = [uint32]$networkValue
        BroadcastValue = [uint32]$broadcastValue
        FirstHostValue = [uint32]$firstHostValue
        LastHostValue = [uint32]$lastHostValue

        UsableHostCount = $usableHostCount
    }
}

function Get-TargetAddresses {
    param(
        [Parameter(Mandatory=$true)]$Subnet,
        [Parameter(Mandatory=$true)][int]$Limit,
        [Parameter(Mandatory=$true)][string]$LocalAddress,
        [switch]$IncludeLocal
    )
    if ([uint64]$Subnet.UsableHostCount -eq 0) { return @() }
    $targetCount = [Math]::Min([uint64]$Limit, [uint64]$Subnet.UsableHostCount)
    if ([uint64]$Subnet.UsableHostCount -gt [uint64]$Limit) {
        $message = "Subnet has $($Subnet.UsableHostCount) usable hosts. Active discovery is limited to $Limit targets."
        $script:Warnings.Add($message)
        Write-DiscoveryLog -Message $message -Level WARN
    }
    $list = New-Object 'System.Collections.Generic.List[string]'
    for ($offset = [uint64]1; $offset -le $targetCount; $offset++) {
        $value = [uint32]([uint64]$Subnet.NetworkValue + $offset)
        $candidate = Convert-UInt32ToIPv4 -Value $value
        if ($IncludeLocal.IsPresent -or $candidate -ne $LocalAddress) { $list.Add($candidate) }
    }
    return @($list | ForEach-Object { $_ })
}

function Invoke-IcmpDiscovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Targets,

        [Parameter(Mandatory = $true)]
        [ValidateRange(100, 5000)]
        [int]$Timeout,

        [Parameter()]
        [ValidateRange(1, 128)]
        [int]$Throttle
    )

    # O parametro Throttle foi mantido por compatibilidade com a interface
    # do script. Esta implementacao prioriza compatibilidade e estabilidade
    # no Windows PowerShell 5.1 e executa as consultas sequencialmente.

    $targetList = @($Targets)

    if ($targetList.Count -eq 0) {
        return @()
    }

    $results = New-Object System.Collections.ArrayList

    $totalTargets = $targetList.Count
    $currentTarget = 0

    foreach ($target in $targetList) {
        $currentTarget++

        $percentComplete = ($currentTarget * 100 / $totalTargets)

        Write-Progress `
            -Activity "OT Network Discovery" `
            -Status (
                "Testing {0} ({1} of {2})" -f
                $target,
                $currentTarget,
                $totalTargets
            ) `
            -PercentComplete $percentComplete

        $ping = New-Object System.Net.NetworkInformation.Ping

        try {
            $reply = $ping.Send(
                [string]$target,
                [int]$Timeout
            )

            $responded = (
                $reply.Status -eq
                [System.Net.NetworkInformation.IPStatus]::Success
            )

            $latency = $null

            if ($responded) {
                $latency = [long]$reply.RoundtripTime
            }

            $result = [pscustomobject][ordered]@{
                IPAddress = [string]$target
                Responded = [bool]$responded
                LatencyMs = $latency
                Status    = $reply.Status.ToString()
            }

            [void]$results.Add($result)
        }
        catch {
            $result = [pscustomobject][ordered]@{
                IPAddress = [string]$target
                Responded = $false
                LatencyMs = $null
                Status    = $_.Exception.Message
            }

            [void]$results.Add($result)
        }
        finally {
            if ($null -ne $ping) {
                $ping.Dispose()
            }
        }
    }

    Write-Progress `
        -Activity "OT Network Discovery" `
        -Completed

    return @(
        $results |
            ForEach-Object {
                $_
            }
    )
}

function Get-DnsNameSafe {
    param([Parameter(Mandatory=$true)][string]$Address)
    try { return ([System.Net.Dns]::GetHostEntry($Address)).HostName } catch { return $null }
}

try {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $script:LogFile = Join-Path $OutputPath 'discovery.log'
    $csvPath = Join-Path $OutputPath 'devices.csv'
    $jsonPath = Join-Path $OutputPath 'devices.json'
    $summaryPath = Join-Path $OutputPath 'summary.txt'
    Write-DiscoveryLog -Message 'OT network discovery started.'

    $configs = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object {
        $null -ne $_.NetAdapter -and $_.NetAdapter.Status -eq 'Up' -and @($_.IPv4Address).Count -gt 0
    })
    if ($InterfaceAlias) {
        $configs = @($configs | Where-Object { $_.InterfaceAlias -eq $InterfaceAlias })
        if (@($configs).Count -eq 0) { throw "Active interface '$InterfaceAlias' was not found." }
    } else {
        $preferred = @($configs | Where-Object { $null -ne $_.IPv4DefaultGateway })
        if (@($preferred).Count -gt 0) { $configs = @($preferred) } else { $configs = @($configs) }
    }
    if (@($configs).Count -eq 0) { throw 'No active IPv4 interface was found.' }
    if (@($configs).Count -gt 1) {
        $message = "Multiple active interfaces found. Using '$(@($configs)[0].InterfaceAlias)'. Use -InterfaceAlias to select another."
        $script:Warnings.Add($message)
        Write-DiscoveryLog -Message $message -Level WARN
    }
    $config = @($configs)[0]
    $addresses = @($config.IPv4Address | Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' })
    if (@($addresses).Count -eq 0) { throw "Interface '$($config.InterfaceAlias)' has no usable IPv4 address." }
    $selected = @($addresses)[0]
    $localIp = [string]$selected.IPAddress
    $prefix = [int]$selected.PrefixLength
    $subnet = Get-SubnetInfo -Address $localIp -PrefixLength $prefix
    Write-DiscoveryLog -Message "Interface: $($config.InterfaceAlias); IPv4: $localIp/$prefix; network: $($subnet.NetworkAddress)/$prefix; broadcast: $($subnet.BroadcastAddress)."

    $icmpResults = @()
    if (-not $SkipActiveDiscovery.IsPresent) {
        $targets = @(Get-TargetAddresses -Subnet $subnet -Limit $MaxHosts -LocalAddress $localIp -IncludeLocal:$IncludeLocalAddress)
        Write-DiscoveryLog -Message "Starting bounded ICMP discovery against $(@($targets).Count) address(es); timeout ${TimeoutMs}ms; throttle $ThrottleLimit."
        $icmpResults = @(Invoke-IcmpDiscovery -Targets $targets -Timeout $TimeoutMs -Throttle $ThrottleLimit)
        $responseCount = @($icmpResults | Where-Object { $_.Responded -eq $true }).Count
        Write-DiscoveryLog -Message "ICMP responses: $responseCount."
        Start-Sleep -Milliseconds 750
    } else {
        Write-DiscoveryLog -Message 'Active ICMP discovery skipped; collecting the existing neighbor cache only.'
    }

    if ($IncludeAllNeighborStates.IsPresent) {
        $allowedStates = @('Reachable','Stale','Delay','Probe','Permanent','Unreachable','Incomplete')
    } else {
        $allowedStates = @('Reachable','Stale','Delay','Probe','Permanent')
    }
    $neighbors = @(Get-NetNeighbor -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.IPAddress -and $_.State.ToString() -in $allowedStates -and $_.IPAddress -notin @('0.0.0.0','255.255.255.255',$subnet.BroadcastAddress)
    })
    Write-DiscoveryLog -Message "Neighbor-cache entries selected: $(@($neighbors).Count)."

    $icmpMap = @{}
    foreach ($result in @($icmpResults)) { if ($result -and $result.IPAddress) { $icmpMap[[string]$result.IPAddress] = $result } }
    $devices = @(
        foreach ($neighbor in @($neighbors)) {
            $result = if ($icmpMap.ContainsKey([string]$neighbor.IPAddress)) { $icmpMap[[string]$neighbor.IPAddress] } else { $null }
            $mac = if ($neighbor.LinkLayerAddress -and $neighbor.LinkLayerAddress -notin @('00-00-00-00-00-00','00:00:00:00:00:00')) { $neighbor.LinkLayerAddress } else { $null }
            [pscustomobject][ordered]@{
                DiscoveredAt = (Get-Date).ToString('o')
                InterfaceAlias = $config.InterfaceAlias
                InterfaceIndex = $config.InterfaceIndex
                IPAddress = [string]$neighbor.IPAddress
                MacAddress = $mac
                NeighborState = $neighbor.State.ToString()
                IcmpResponded = if ($result) { [bool]$result.Responded } else { $false }
                LatencyMs = if ($result) { $result.LatencyMs } else { $null }
                DnsName = if ($ResolveDns.IsPresent) { Get-DnsNameSafe -Address ([string]$neighbor.IPAddress) } else { $null }
                IsLocalAddress = ([string]$neighbor.IPAddress -eq $localIp)
                Network = "$($subnet.NetworkAddress)/$prefix"
            }
        }
    )
    $devices = @($devices | Sort-Object @{Expression={Convert-IPv4ToUInt32 -Address $_.IPAddress}} -Unique)

    if (@($devices).Count -gt 0) {
        $devices | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        $devices | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    } else {
        'DiscoveredAt,InterfaceAlias,InterfaceIndex,IPAddress,MacAddress,NeighborState,IcmpResponded,LatencyMs,DnsName,IsLocalAddress,Network' | Set-Content -LiteralPath $csvPath -Encoding UTF8
        '[]' | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    }

    $responseCount = @($icmpResults | Where-Object { $_.Responded -eq $true }).Count
    $summary = @(
        'OT Network Discovery Summary'
        '============================'
        ''
        "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
        "Computer: $env:COMPUTERNAME"
        "User: $env:USERNAME"
        "PowerShell: $($PSVersionTable.PSVersion)"
        "Interface: $($config.InterfaceAlias)"
        "Interface index: $($config.InterfaceIndex)"
        "Local IPv4: $localIp/$prefix"
        "Network: $($subnet.NetworkAddress)/$prefix"
        "Broadcast: $($subnet.BroadcastAddress)"
        "Usable hosts: $($subnet.UsableHostCount)"
        "Active discovery: $(-not $SkipActiveDiscovery.IsPresent)"
        "ICMP targets: $(@($icmpResults).Count)"
        "ICMP responses: $responseCount"
        "Neighbor records exported: $(@($devices).Count)"
        "Warnings: $($script:Warnings.Count)"
        ''
        'Note: absence of an ICMP response does not prove that a device is offline.'
    )
    $summary | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-DiscoveryLog -Message "Exported $(@($devices).Count) neighbor record(s)."
    Write-DiscoveryLog -Message "Reports created in: $OutputPath"

    [pscustomobject][ordered]@{
        OutputPath = (Resolve-Path $OutputPath).Path
        Interface = $config.InterfaceAlias
        LocalAddress = "$localIp/$prefix"
        Network = "$($subnet.NetworkAddress)/$prefix"
        Devices = @($devices).Count
        IcmpResponses = $responseCount
        Warnings = $script:Warnings.Count
    }
} catch {
    Write-DiscoveryLog -Message $_.Exception.Message -Level ERROR
    exit 1
}




