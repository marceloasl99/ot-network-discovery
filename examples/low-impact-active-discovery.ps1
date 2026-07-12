# Use only after confirming scope and authorization.
..\OT-NetworkDiscovery.ps1 `
  -InterfaceAlias "Ethernet" `
  -TimeoutMs 800 `
  -ThrottleLimit 8 `
  -MaxHosts 254 `
  -ResolveDns
