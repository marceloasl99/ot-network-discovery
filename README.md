# OT Network Discovery for Windows

A lightweight PowerShell utility for authorized IPv4 neighbor discovery on Windows 10/11. The tool identifies the active interface, calculates the complete CIDR range correctly, performs optional bounded ICMP discovery, reads the Windows neighbor cache and exports structured CSV, JSON, TXT and log reports.

> Use this project only on networks and systems you own or are explicitly authorized to assess. The tool is intended for inventory support and visibility, not as a substitute for an approved OT asset-discovery platform.

## Why this version

The original script assumed a `/24`-style network by changing only the last IPv4 octet, relied on broadcast ping behavior, exported only `Reachable` neighbors and had limited error handling. This version supports arbitrary IPv4 prefix lengths, multiple interfaces, stale but useful ARP/neighbor entries, bounded concurrency and repeatable reports.

## Features

- Runs on Windows PowerShell 5.1 and PowerShell 7+
- No administrator requirement for the default workflow
- Selects an active interface automatically or by alias
- Handles arbitrary IPv4 CIDR prefixes
- Avoids dependence on directed-broadcast replies
- Optional passive-only mode
- Bounded ICMP discovery with timeout, concurrency and host limits
- Collects Reachable, Stale, Delay, Probe and Permanent neighbors by default
- Optional reverse-DNS lookup
- CSV, JSON, summary and detailed log output
- Explicit warnings for large subnets
- Does not scan TCP/UDP ports or attempt authentication

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7+
- `Get-NetIPConfiguration` and `Get-NetNeighbor`
- Access to an authorized local IPv4 network

## Quick start

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\OT-NetworkDiscovery.ps1
```

The output folder is created in the current directory:

```text
OT_Discovery_YYYYMMDD_HHMMSS/
├── discovery.log
├── devices.csv
├── devices.json
└── summary.txt
```

## Usage examples

### Default bounded discovery

```powershell
.\OT-NetworkDiscovery.ps1
```

### Select a specific interface

```powershell
.\OT-NetworkDiscovery.ps1 -InterfaceAlias "Ethernet"
```

### Passive-only neighbor-cache collection

```powershell
.\OT-NetworkDiscovery.ps1 -SkipActiveDiscovery
```

### Include DNS names

```powershell
.\OT-NetworkDiscovery.ps1 -ResolveDns
```

### Limit activity for a sensitive OT segment

```powershell
.\OT-NetworkDiscovery.ps1 `
  -InterfaceAlias "Ethernet" `
  -TimeoutMs 800 `
  -ThrottleLimit 8 `
  -MaxHosts 254
```

### Include every neighbor state

```powershell
.\OT-NetworkDiscovery.ps1 -IncludeAllNeighborStates
```

### Custom report directory

```powershell
.\OT-NetworkDiscovery.ps1 -OutputPath "C:\Temp\OT-Inventory"
```

## Parameters

| Parameter | Purpose | Default |
|---|---|---|
| `OutputPath` | Report directory | Timestamped folder |
| `TimeoutMs` | ICMP timeout per address | `450` ms |
| `ThrottleLimit` | Maximum parallel ICMP workers | `32` |
| `MaxHosts` | Maximum active targets | `1024` |
| `SkipActiveDiscovery` | Reads existing neighbor cache only | Disabled |
| `IncludeAllNeighborStates` | Includes incomplete and unreachable entries | Disabled |
| `ResolveDns` | Attempts reverse-DNS lookup | Disabled |
| `IncludeLocalAddress` | Includes the local address as an ICMP target | Disabled |
| `InterfaceAlias` | Chooses an interface explicitly | Automatic |

## CSV fields

- `DiscoveredAt`
- `InterfaceAlias`
- `InterfaceIndex`
- `IPAddress`
- `MacAddress`
- `NeighborState`
- `IcmpResponded`
- `LatencyMs`
- `DnsName`
- `IsLocalAddress`
- `Network`

## OT operational considerations

- Start with `-SkipActiveDiscovery` on sensitive or legacy networks.
- If active discovery is approved, use a low `ThrottleLimit` such as `4` or `8`.
- A missing ping response does not prove that an asset is offline.
- Windows neighbor-cache visibility is limited to the local Layer-2 broadcast domain and traffic the workstation can observe.
- Routed devices may not appear with their own MAC address.
- Reverse DNS can be slow or unavailable.
- Validate results against switch MAC tables, DHCP, firewall logs, SCADA inventories and approved asset-management sources.

## Security and privacy

The reports contain real IP addresses, MAC addresses, interface names, hostnames and workstation metadata. Review report files before publishing or sharing them.

The script does not:

- scan service ports;
- authenticate to devices;
- modify device configuration;
- exploit vulnerabilities;
- install software;
- require stored credentials.

## Troubleshooting

### No interface found

```powershell
Get-NetIPConfiguration
Get-NetAdapter | Where-Object Status -eq Up
```

Select an interface explicitly:

```powershell
.\OT-NetworkDiscovery.ps1 -InterfaceAlias "Ethernet 2"
```

### Few devices are found

Generate normal authorized traffic first, then use passive mode:

```powershell
.\OT-NetworkDiscovery.ps1 -SkipActiveDiscovery -IncludeAllNeighborStates
```

Inspect the cache directly:

```powershell
Get-NetNeighbor -AddressFamily IPv4 | Sort-Object InterfaceIndex,IPAddress
```

### Execution policy blocks the script

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

### Large subnet warning

The script intentionally limits active targets with `MaxHosts`. Increase the limit only after confirming scope and authorization.

## Validation

Parse the script without running discovery:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  ".\OT-NetworkDiscovery.ps1",
  [ref]$null,
  [ref]$errors
) | Out-Null
$errors
```

## License

MIT License. See [LICENSE](LICENSE).
