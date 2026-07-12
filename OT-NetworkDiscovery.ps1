#requires -Version 5.1
<#
.SYNOPSIS
    Passive-first IPv4 neighbor discovery and reporting for authorized Windows networks.
.DESCRIPTION
    Collects the local IPv4 configuration, safely calculates the network range,
    optionally performs bounded ICMP discovery, refreshes the Windows neighbor cache,
    and exports TXT, CSV and JSON reports. No administrator privileges are required
    for the default workflow.
.NOTES
    Use only on networks you own or are explicitly authorized to assess.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) ("OT_Discovery_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
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
$script:Warnings = [System.Collections.Generic.List[string]]::new()
function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
    Add-Content -LiteralPath $script:LogTxt -Value $line -Encoding UTF8
    if($Level -eq 'WARN'){ Write-Warning $Message } elseif($Level -eq 'ERROR'){ Write-Error $Message -ErrorAction Continue } else { Write-Host $line }
}
function Convert-IPv4ToUInt32 {
    param([Parameter(Mandatory)][string]$Address)
    $bytes=[Net.IPAddress]::Parse($Address).GetAddressBytes();[Array]::Reverse($bytes)
    [BitConverter]::ToUInt32($bytes,0)
}
function Convert-UInt32ToIPv4 {
    param([Parameter(Mandatory)][uint32]$Value)
    $bytes=[BitConverter]::GetBytes($Value);[Array]::Reverse($bytes)
    ([Net.IPAddress]::new($bytes)).IPAddressToString
}
function Get-SubnetInfo {
    param([string]$Address,[ValidateRange(0,32)][int]$PrefixLength)
    $ipValue=Convert-IPv4ToUInt32 $Address
    $maskValue=if($PrefixLength -eq 0){[uint32]0}else{[uint32]([uint64]0xFFFFFFFF -shl (32-$PrefixLength))}
    $network=[uint32]($ipValue -band $maskValue);$broadcast=[uint32]($network -bor ([uint32]0xFFFFFFFF -bxor $maskValue))
    $usable=[math]::Max(0,([uint64]$broadcast-[uint64]$network-1))
    [pscustomobject]@{NetworkAddress=Convert-UInt32ToIPv4 $network;BroadcastAddress=Convert-UInt32ToIPv4 $broadcast;PrefixLength=$PrefixLength;NetworkValue=$network;BroadcastValue=$broadcast;UsableHostCount=$usable}
}
function Get-TargetAddresses {
    param($Subnet,[int]$Limit,[string]$LocalAddress,[switch]$IncludeLocal)
    $count=[math]::Min([uint64]$Limit,[uint64]$Subnet.UsableHostCount)
    if($Subnet.UsableHostCount -gt $Limit){$msg="Subnet contains $($Subnet.UsableHostCount) usable hosts; active discovery is limited to $Limit.";$script:Warnings.Add($msg);Write-Log $msg WARN}
    for($offset=[uint64]1;$offset -le $count;$offset++){
        $candidate=Convert-UInt32ToIPv4 ([uint32]([uint64]$Subnet.NetworkValue+$offset))
        if($IncludeLocal -or $candidate -ne $LocalAddress){$candidate}
    }
}
function Invoke-IcmpDiscovery {
    param([string[]]$Targets,[int]$Timeout,[int]$Throttle)
    if(-not $Targets){return @()}
    $pool=[RunspaceFactory]::CreateRunspacePool(1,$Throttle);$pool.Open();$jobs=[Collections.Generic.List[object]]::new()
    $worker={param($Target,$TimeoutMs)
        $ping=[Net.NetworkInformation.Ping]::new()
        try{$reply=$ping.Send($Target,$TimeoutMs);[pscustomobject]@{IPAddress=$Target;Responded=($reply.Status -eq 'Success');LatencyMs=if($reply.Status -eq 'Success'){$reply.RoundtripTime}else{$null};Status=$reply.Status.ToString()}}
        catch{[pscustomobject]@{IPAddress=$Target;Responded=$false;LatencyMs=$null;Status=$_.Exception.Message}}
        finally{$ping.Dispose()}
    }
    foreach($target in $Targets){$ps=[PowerShell]::Create().AddScript($worker).AddArgument($target).AddArgument($Timeout);$ps.RunspacePool=$pool;$jobs.Add([pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke()})}
    $results=foreach($job in $jobs){try{$job.PowerShell.EndInvoke($job.Handle)}finally{$job.PowerShell.Dispose()}}
    $pool.Close();$pool.Dispose();@($results)
}
function Get-DnsNameSafe {
    param([string]$Address)
    try{([Net.Dns]::GetHostEntry($Address)).HostName}catch{$null}
}
try {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $script:LogTxt=Join-Path $OutputPath 'discovery.log'
    $csvPath=Join-Path $OutputPath 'devices.csv';$jsonPath=Join-Path $OutputPath 'devices.json';$summaryPath=Join-Path $OutputPath 'summary.txt'
    Write-Log 'OT network discovery started.'
    $configs=@(Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address})
    if($InterfaceAlias){$configs=@($configs | Where-Object {$_.InterfaceAlias -eq $InterfaceAlias});if(-not $configs){throw "Active interface '$InterfaceAlias' was not found."}}
    else{$preferred=@($configs | Where-Object {$_.IPv4DefaultGateway});$configs=if($preferred){$preferred}else{$configs}}
    if(-not $configs){throw 'No active IPv4 interface was found.'}
    if($configs.Count -gt 1){$msg="Multiple active interfaces found. Using '$($configs[0].InterfaceAlias)'. Use -InterfaceAlias to select another.";$script:Warnings.Add($msg);Write-Log $msg WARN}
    $config=$configs[0];$address=@($config.IPv4Address | Where-Object {$_.IPAddress -notlike '169.254.*'})[0]
    if(-not $address){throw 'The selected interface has no usable non-APIPA IPv4 address.'}
    $ip=$address.IPAddress;$prefix=[int]$address.PrefixLength;$subnet=Get-SubnetInfo $ip $prefix
    Write-Log "Interface: $($config.InterfaceAlias); IPv4: $ip/$prefix; Network: $($subnet.NetworkAddress); Broadcast: $($subnet.BroadcastAddress)."
    $icmp=@()
    if(-not $SkipActiveDiscovery){
        $targets=@(Get-TargetAddresses $subnet $MaxHosts $ip -IncludeLocal:$IncludeLocalAddress)
        Write-Log "Starting bounded ICMP discovery against $($targets.Count) address(es), timeout ${TimeoutMs}ms, throttle $ThrottleLimit."
        $icmp=@(Invoke-IcmpDiscovery $targets $TimeoutMs $ThrottleLimit)
        Write-Log "ICMP responses: $(@($icmp | Where-Object Responded).Count)."
        Start-Sleep -Milliseconds 750
    } else {Write-Log 'Active ICMP discovery skipped; collecting the existing neighbor cache only.'}
    $allowedStates=if($IncludeAllNeighborStates){@('Reachable','Stale','Delay','Probe','Permanent','Unreachable','Incomplete')}else{@('Reachable','Stale','Delay','Probe','Permanent')}
    $neighbors=@(Get-NetNeighbor -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.State.ToString() -in $allowedStates -and $_.IPAddress -ne '255.255.255.255' -and $_.IPAddress -ne $subnet.BroadcastAddress})
    $icmpMap=@{};foreach($r in $icmp){$icmpMap[$r.IPAddress]=$r}
    $devices=foreach($neighbor in $neighbors){
        $mac=if($neighbor.LinkLayerAddress -and $neighbor.LinkLayerAddress -ne '00-00-00-00-00-00'){$neighbor.LinkLayerAddress}else{$null}
        $result=$icmpMap[$neighbor.IPAddress]
        [pscustomobject][ordered]@{DiscoveredAt=(Get-Date).ToString('o');InterfaceAlias=$config.InterfaceAlias;InterfaceIndex=$config.InterfaceIndex;IPAddress=$neighbor.IPAddress;MacAddress=$mac;NeighborState=$neighbor.State.ToString();IcmpResponded=if($result){[bool]$result.Responded}else{$false};LatencyMs=if($result){$result.LatencyMs}else{$null};DnsName=if($ResolveDns){Get-DnsNameSafe $neighbor.IPAddress}else{$null};IsLocalAddress=($neighbor.IPAddress -eq $ip);Network="$($subnet.NetworkAddress)/$prefix"}
    }
    $devices=@($devices | Sort-Object {[version]$_.IPAddress} -Unique)
    $devices | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    $devices | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $summary=@("OT Network Discovery Summary","Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')","Computer: $env:COMPUTERNAME","User: $env:USERNAME","PowerShell: $($PSVersionTable.PSVersion)","Interface: $($config.InterfaceAlias) (index $($config.InterfaceIndex))","Local IPv4: $ip/$prefix","Network: $($subnet.NetworkAddress)/$prefix","Broadcast: $($subnet.BroadcastAddress)","Active discovery: $(-not $SkipActiveDiscovery)","ICMP targets: $($icmp.Count)","ICMP responses: $(@($icmp | Where-Object Responded).Count)","Neighbor records exported: $($devices.Count)","Warnings: $($script:Warnings.Count)","","Important: absence of an ICMP response does not mean a device is offline; many OT devices block ICMP.")
    $summary | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Log "Exported $($devices.Count) neighbor record(s)."
    Write-Log "Reports: $OutputPath"
    [pscustomobject]@{OutputPath=(Resolve-Path $OutputPath).Path;Interface=$config.InterfaceAlias;LocalAddress="$ip/$prefix";Network="$($subnet.NetworkAddress)/$prefix";Devices=$devices.Count;IcmpResponses=@($icmp | Where-Object Responded).Count;Warnings=$script:Warnings.Count}
} catch {
    if($script:LogTxt){Write-Log $_.Exception.Message ERROR}else{Write-Error $_.Exception.Message}
    exit 1
}
