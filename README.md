# OT Network Discovery

Lightweight PowerShell 5.1+ utility for authorized IPv4 neighbor discovery and OT network inventory on Windows 10/11.

## Features

- Correct CIDR, network, netmask and broadcast calculation
- Windows PowerShell 5.1 compatibility
- Automatic or explicit interface selection
- Passive-only cache collection
- Bounded sequential ICMP discovery with visible progress
- Configurable timeout and maximum target count
- Optional reverse-DNS lookup
- CSV, JSON, summary and log reports
- Useful Windows neighbor states beyond `Reachable`
- No port scans, authentication attempts or device changes

## First run

```powershell
Unblock-File .\OT-NetworkDiscovery.ps1
Set-ExecutionPolicy -Scope Process Bypass -Force
.\OT-NetworkDiscovery.ps1 -SkipActiveDiscovery -IncludeAllNeighborStates
```

## Controlled active discovery

Test a limited range first:

```powershell
.\OT-NetworkDiscovery.ps1 `
  -InterfaceAlias "Wi-Fi" `
  -TimeoutMs 200 `
  -MaxHosts 20
```

Run a complete `/24` after validation:

```powershell
.\OT-NetworkDiscovery.ps1 `
  -InterfaceAlias "Wi-Fi" `
  -TimeoutMs 200 `
  -MaxHosts 254
```

> Active discovery is sequential for maximum compatibility with Windows PowerShell 5.1. `ThrottleLimit` remains accepted for command-line compatibility but is not used for parallel execution in this release.

## Output

```text
OT_Discovery_YYYYMMDD_HHMMSS/
├── discovery.log
├── devices.csv
├── devices.json
└── summary.txt
```

## Parameters

- `OutputPath`: custom report directory
- `TimeoutMs`: ICMP timeout, 100–5000 ms
- `MaxHosts`: maximum active targets
- `SkipActiveDiscovery`: neighbor-cache-only mode
- `IncludeAllNeighborStates`: includes incomplete and unreachable entries
- `ResolveDns`: attempts reverse DNS
- `IncludeLocalAddress`: includes the workstation IP among targets
- `InterfaceAlias`: selects an interface explicitly

## Operational guidance

Start in passive mode on sensitive OT networks. A missing ICMP response does not prove that a device is offline. Windows neighbor discovery is limited to traffic and Layer-2 neighbors visible to the workstation. Validate findings against switch MAC tables, DHCP, firewall logs, SCADA inventories and approved asset-management sources.

## Syntax validation

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path '.\OT-NetworkDiscovery.ps1'),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors
```

## License

MIT. See [LICENSE](LICENSE).
