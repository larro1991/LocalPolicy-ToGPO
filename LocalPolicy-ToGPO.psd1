@{
    # Module manifest for LocalPolicy-ToGPO
    # Migrate local policy settings to domain Group Policy Objects

    RootModule        = 'LocalPolicy-ToGPO.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd4e5f6a7-1b02-4d8e-cf90-5b6c7d8e9f01'
    Author            = 'Larry Roberts, Independent Consultant'
    CompanyName       = 'Independent Consultant'
    Copyright         = '(c) 2026 Larry Roberts. All rights reserved.'
    Description       = 'Migrate local policy settings to domain Group Policy Objects. Reads local firewall rules and security policy from servers and creates equivalent GPO settings for centralized management. Never modifies local policy — read-only on source, write to GPO only. Requires GroupPolicy and NetSecurity modules.'

    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Get-LocalFirewallPolicy'
        'Get-LocalSecurityPolicy'
        'Copy-FirewallToGPO'
        'Copy-SecurityPolicyToGPO'
        'Compare-PolicyCompliance'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('GroupPolicy', 'GPO', 'Firewall', 'LocalPolicy', 'Migration', 'Security', 'WindowsFirewall')
            LicenseUri   = 'https://github.com/larro1991/LocalPolicy-ToGPO/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/larro1991/LocalPolicy-ToGPO'
            ReleaseNotes = 'Initial release. Read-only migration of local firewall and security policy to domain GPOs.'
        }
    }
}
