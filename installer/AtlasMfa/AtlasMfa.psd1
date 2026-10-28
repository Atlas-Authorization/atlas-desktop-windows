@{
  RootModule        = 'AtlasMfa.psm1'
  ModuleVersion     = '0.2.0'
  GUID              = '6b1b2f0e-7a53-4b6d-9d0e-3a5f6a7c1e42'
  Author            = 'Atlas'
  Description       = 'Asks for the Atlas second factor in a PowerShell session before a sensitive step.'
  PowerShellVersion = '5.1'
  FunctionsToExport = @('Invoke-AtlasMfa', 'Enter-AtlasElevation')
  CmdletsToExport   = @()
  VariablesToExport = @()
  AliasesToExport   = @()
}
