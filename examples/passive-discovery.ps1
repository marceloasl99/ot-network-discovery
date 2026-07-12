# Recommended first run on a sensitive OT segment.
..\OT-NetworkDiscovery.ps1 `
  -InterfaceAlias "Ethernet" `
  -SkipActiveDiscovery `
  -IncludeAllNeighborStates `
  -ResolveDns
