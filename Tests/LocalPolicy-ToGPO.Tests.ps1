#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for the LocalPolicy-ToGPO module.
.DESCRIPTION
    Tests module loading, parameter validation, mock-based function logic,
    and manifest correctness.
#>

BeforeAll {
    $ModulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ModuleName = 'LocalPolicy-ToGPO'
    $ManifestPath = Join-Path $ModulePath "$ModuleName.psd1"

    # Remove module if loaded, then import fresh
    if (Get-Module -Name $ModuleName) {
        Remove-Module -Name $ModuleName -Force
    }
    Import-Module $ManifestPath -Force
}

AfterAll {
    if (Get-Module -Name 'LocalPolicy-ToGPO') {
        Remove-Module -Name 'LocalPolicy-ToGPO' -Force
    }
}

# ==============================================================================
# Module Loading Tests
# ==============================================================================
Describe 'Module Loading' {
    It 'Should import the module without errors' {
        $module = Get-Module -Name 'LocalPolicy-ToGPO'
        $module | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 5 public functions' {
        $module = Get-Module -Name 'LocalPolicy-ToGPO'
        $module.ExportedFunctions.Count | Should -Be 5
    }

    It 'Should export Get-LocalFirewallPolicy' {
        Get-Command -Module 'LocalPolicy-ToGPO' -Name 'Get-LocalFirewallPolicy' | Should -Not -BeNullOrEmpty
    }

    It 'Should export Get-LocalSecurityPolicy' {
        Get-Command -Module 'LocalPolicy-ToGPO' -Name 'Get-LocalSecurityPolicy' | Should -Not -BeNullOrEmpty
    }

    It 'Should export Copy-FirewallToGPO' {
        Get-Command -Module 'LocalPolicy-ToGPO' -Name 'Copy-FirewallToGPO' | Should -Not -BeNullOrEmpty
    }

    It 'Should export Copy-SecurityPolicyToGPO' {
        Get-Command -Module 'LocalPolicy-ToGPO' -Name 'Copy-SecurityPolicyToGPO' | Should -Not -BeNullOrEmpty
    }

    It 'Should export Compare-PolicyCompliance' {
        Get-Command -Module 'LocalPolicy-ToGPO' -Name 'Compare-PolicyCompliance' | Should -Not -BeNullOrEmpty
    }

    It 'Should NOT export New-HtmlDashboard (private function)' {
        $exported = Get-Command -Module 'LocalPolicy-ToGPO' | Select-Object -ExpandProperty Name
        $exported | Should -Not -Contain 'New-HtmlDashboard'
    }
}

# ==============================================================================
# Manifest Validation
# ==============================================================================
Describe 'Manifest Validation' {
    It 'Should have a valid module manifest' {
        { Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Should have the correct GUID' {
        $manifest = Test-ModuleManifest -Path $ManifestPath
        $manifest.GUID.ToString() | Should -Be 'd4e5f6a7-1b02-4d8e-cf90-5b6c7d8e9f01'
    }

    It 'Should require PowerShell 5.1' {
        $manifest = Test-ModuleManifest -Path $ManifestPath
        $manifest.PowerShellVersion.ToString() | Should -Be '5.1'
    }

    It 'Should have the correct author' {
        $manifest = Test-ModuleManifest -Path $ManifestPath
        $manifest.Author | Should -BeLike '*Larry Roberts*'
    }

    It 'Should list required tags' {
        $manifest = Test-ModuleManifest -Path $ManifestPath
        $tags = $manifest.PrivateData.PSData.Tags
        $tags | Should -Contain 'GroupPolicy'
        $tags | Should -Contain 'GPO'
        $tags | Should -Contain 'Firewall'
        $tags | Should -Contain 'LocalPolicy'
        $tags | Should -Contain 'Migration'
    }
}

# ==============================================================================
# Parameter Validation Tests
# ==============================================================================
Describe 'Parameter Validation' {
    Context 'Get-LocalFirewallPolicy' {
        It 'Should have a ProfileFilter parameter with ValidateSet' {
            $cmd = Get-Command -Name 'Get-LocalFirewallPolicy'
            $param = $cmd.Parameters['ProfileFilter']
            $param | Should -Not -BeNullOrEmpty
            $validateSet = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'Domain'
            $validateSet.ValidValues | Should -Contain 'Private'
            $validateSet.ValidValues | Should -Contain 'Public'
            $validateSet.ValidValues | Should -Contain 'Any'
        }

        It 'Should accept pipeline input for ComputerName' {
            $cmd = Get-Command -Name 'Get-LocalFirewallPolicy'
            $param = $cmd.Parameters['ComputerName']
            $param.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.ValueFromPipeline
            } | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Copy-FirewallToGPO' {
        It 'Should require -SourceComputer as mandatory' {
            $cmd = Get-Command -Name 'Copy-FirewallToGPO'
            $param = $cmd.Parameters['SourceComputer']
            $mandatory = $param.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
            }
            $mandatory | Should -Not -BeNullOrEmpty
        }

        It 'Should require -GPOName as mandatory' {
            $cmd = Get-Command -Name 'Copy-FirewallToGPO'
            $param = $cmd.Parameters['GPOName']
            $mandatory = $param.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
            }
            $mandatory | Should -Not -BeNullOrEmpty
        }

        It 'Should support -WhatIf' {
            $cmd = Get-Command -Name 'Copy-FirewallToGPO'
            $cmd.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }

        It 'Should support -Confirm' {
            $cmd = Get-Command -Name 'Copy-FirewallToGPO'
            $cmd.Parameters.ContainsKey('Confirm') | Should -Be $true
        }
    }

    Context 'Copy-SecurityPolicyToGPO' {
        It 'Should require -SourceComputer as mandatory' {
            $cmd = Get-Command -Name 'Copy-SecurityPolicyToGPO'
            $param = $cmd.Parameters['SourceComputer']
            $mandatory = $param.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
            }
            $mandatory | Should -Not -BeNullOrEmpty
        }

        It 'Should require -GPOName as mandatory' {
            $cmd = Get-Command -Name 'Copy-SecurityPolicyToGPO'
            $param = $cmd.Parameters['GPOName']
            $mandatory = $param.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
            }
            $mandatory | Should -Not -BeNullOrEmpty
        }

        It 'Should have a Categories parameter with ValidateSet' {
            $cmd = Get-Command -Name 'Copy-SecurityPolicyToGPO'
            $param = $cmd.Parameters['Categories']
            $param | Should -Not -BeNullOrEmpty
            $validateSet = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'SystemAccess'
            $validateSet.ValidValues | Should -Contain 'AuditPolicy'
            $validateSet.ValidValues | Should -Contain 'UserRights'
            $validateSet.ValidValues | Should -Contain 'SecurityOptions'
            $validateSet.ValidValues | Should -Contain 'All'
        }

        It 'Should support -WhatIf' {
            $cmd = Get-Command -Name 'Copy-SecurityPolicyToGPO'
            $cmd.Parameters.ContainsKey('WhatIf') | Should -Be $true
        }
    }

    Context 'Compare-PolicyCompliance' {
        It 'Should require -ComputerName as mandatory' {
            $cmd = Get-Command -Name 'Compare-PolicyCompliance'
            $param = $cmd.Parameters['ComputerName']
            $mandatory = $param.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
            }
            $mandatory | Should -Not -BeNullOrEmpty
        }

        It 'Should require -GPOName as mandatory' {
            $cmd = Get-Command -Name 'Compare-PolicyCompliance'
            $param = $cmd.Parameters['GPOName']
            $mandatory = $param.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
            }
            $mandatory | Should -Not -BeNullOrEmpty
        }

        It 'Should have a CompareType parameter with ValidateSet' {
            $cmd = Get-Command -Name 'Compare-PolicyCompliance'
            $param = $cmd.Parameters['CompareType']
            $param | Should -Not -BeNullOrEmpty
            $validateSet = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet | Should -Not -BeNullOrEmpty
            $validateSet.ValidValues | Should -Contain 'Firewall'
            $validateSet.ValidValues | Should -Contain 'SecurityPolicy'
            $validateSet.ValidValues | Should -Contain 'Both'
        }
    }
}

# ==============================================================================
# Mock-Based Function Tests
# ==============================================================================
Describe 'Get-LocalFirewallPolicy (Mocked)' {
    BeforeAll {
        # Mock firewall rules -- mix of local and GPO-delivered
        $mockRules = @(
            [PSCustomObject]@{
                DisplayName          = 'Allow HTTP Inbound'
                Direction            = 'Inbound'
                Action               = 'Allow'
                Enabled              = 'True'
                Profile              = 'Any'
                Description          = 'HTTP web traffic'
                PolicyStoreSourceType = 'Local'
            },
            [PSCustomObject]@{
                DisplayName          = 'Allow HTTPS Inbound'
                Direction            = 'Inbound'
                Action               = 'Allow'
                Enabled              = 'True'
                Profile              = 'Domain'
                Description          = 'HTTPS web traffic'
                PolicyStoreSourceType = 'Local'
            },
            [PSCustomObject]@{
                DisplayName          = 'GPO Rule - Should Be Excluded'
                Direction            = 'Inbound'
                Action               = 'Allow'
                Enabled              = 'True'
                Profile              = 'Domain'
                Description          = 'This comes from GPO'
                PolicyStoreSourceType = 'GroupPolicy'
            },
            [PSCustomObject]@{
                DisplayName          = 'Disabled Local Rule'
                Direction            = 'Outbound'
                Action               = 'Block'
                Enabled              = 'False'
                Profile              = 'Private'
                Description          = 'A disabled rule'
                PolicyStoreSourceType = 'Local'
            }
        )

        $mockAddressFilter = [PSCustomObject]@{
            LocalAddress  = 'Any'
            RemoteAddress = '10.0.0.0/8'
        }
        $mockPortFilter = [PSCustomObject]@{
            Protocol  = 'TCP'
            LocalPort = '80'
            RemotePort = 'Any'
        }
        $mockAppFilter = [PSCustomObject]@{
            Program = 'C:\inetpub\w3wp.exe'
        }
    }

    It 'Should filter out GPO-delivered rules' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Invoke-Command {
            # Simulate the remote script block behavior
            $localRules = $mockRules | Where-Object { $_.PolicyStoreSourceType -ne 'GroupPolicy' }
            $localRules = $localRules | Where-Object { $_.Enabled -eq 'True' }

            foreach ($rule in $localRules) {
                [PSCustomObject]@{
                    DisplayName   = $rule.DisplayName
                    Direction     = $rule.Direction
                    Action        = $rule.Action
                    Protocol      = 'TCP'
                    LocalPort     = '80'
                    RemotePort    = 'Any'
                    LocalAddress  = 'Any'
                    RemoteAddress = '10.0.0.0/8'
                    Program       = 'C:\inetpub\w3wp.exe'
                    Profile       = $rule.Profile
                    Enabled       = $true
                    Description   = $rule.Description
                    PolicySource  = 'Local'
                }
            }
        }

        $results = Get-LocalFirewallPolicy -ComputerName 'SVR-TEST-01'
        $results | Should -Not -BeNullOrEmpty
        $results.DisplayName | Should -Not -Contain 'GPO Rule - Should Be Excluded'
    }

    It 'Should return objects with expected properties' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Invoke-Command {
            [PSCustomObject]@{
                DisplayName   = 'Allow HTTP Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '80'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = '10.0.0.0/8'
                Program       = 'C:\inetpub\w3wp.exe'
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTP web traffic'
                PolicySource  = 'Local'
            }
        }

        $results = Get-LocalFirewallPolicy -ComputerName 'SVR-TEST-01'
        $result = $results | Select-Object -First 1

        $result.PSObject.Properties.Name | Should -Contain 'ComputerName'
        $result.PSObject.Properties.Name | Should -Contain 'DisplayName'
        $result.PSObject.Properties.Name | Should -Contain 'Direction'
        $result.PSObject.Properties.Name | Should -Contain 'Action'
        $result.PSObject.Properties.Name | Should -Contain 'Protocol'
        $result.PSObject.Properties.Name | Should -Contain 'LocalPort'
        $result.PSObject.Properties.Name | Should -Contain 'RemotePort'
        $result.PSObject.Properties.Name | Should -Contain 'LocalAddress'
        $result.PSObject.Properties.Name | Should -Contain 'RemoteAddress'
        $result.PSObject.Properties.Name | Should -Contain 'Program'
        $result.PSObject.Properties.Name | Should -Contain 'Profile'
        $result.PSObject.Properties.Name | Should -Contain 'Enabled'
        $result.PSObject.Properties.Name | Should -Contain 'Description'
        $result.PSObject.Properties.Name | Should -Contain 'PolicySource'
    }

    It 'Should set PolicySource to Local for all returned rules' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Invoke-Command {
            [PSCustomObject]@{
                DisplayName   = 'Allow HTTP Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '80'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTP'
                PolicySource  = 'Local'
            }
        }

        $results = Get-LocalFirewallPolicy -ComputerName 'SVR-TEST-01'
        $results | ForEach-Object { $_.PolicySource | Should -Be 'Local' }
    }

    It 'Should only return enabled rules by default' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Invoke-Command {
            # Simulates the script block returning only enabled, local rules
            [PSCustomObject]@{
                DisplayName   = 'Allow HTTP Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '80'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTP'
                PolicySource  = 'Local'
            }
        }

        $results = Get-LocalFirewallPolicy -ComputerName 'SVR-TEST-01'
        $results | ForEach-Object { $_.Enabled | Should -Be $true }
    }
}

Describe 'Get-LocalSecurityPolicy (Mocked)' {
    It 'Should parse secedit .inf output into structured objects' {
        $mockInfContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 1
AuditPolicyChange = 3
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeDenyNetworkLogonRight = *S-1-5-32-546
[Registry Values]
MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\DefaultLevel=4,0
"@

        Mock -ModuleName 'LocalPolicy-ToGPO' Invoke-Command { return $mockInfContent }

        $results = Get-LocalSecurityPolicy -ComputerName 'SVR-TEST-01'
        $results | Should -Not -BeNullOrEmpty

        # Verify we got settings from multiple sections
        $categories = $results | Select-Object -ExpandProperty Category -Unique
        $categories | Should -Contain 'SystemAccess'
        $categories | Should -Contain 'AuditPolicy'
        $categories | Should -Contain 'UserRights'
        $categories | Should -Contain 'SecurityOptions'
    }

    It 'Should return correct property values for System Access settings' {
        $mockInfContent = @"
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
"@

        Mock -ModuleName 'LocalPolicy-ToGPO' Invoke-Command { return $mockInfContent }

        $results = Get-LocalSecurityPolicy -ComputerName 'SVR-TEST-01'
        $pwdLength = $results | Where-Object { $_.SettingName -eq 'MinimumPasswordLength' }
        $pwdLength | Should -Not -BeNullOrEmpty
        $pwdLength.SettingValue | Should -Be '14'
        $pwdLength.Category | Should -Be 'SystemAccess'
    }

    It 'Should return ComputerName on each result' {
        $mockInfContent = @"
[System Access]
MinimumPasswordLength = 14
"@

        Mock -ModuleName 'LocalPolicy-ToGPO' Invoke-Command { return $mockInfContent }

        $results = Get-LocalSecurityPolicy -ComputerName 'SVR-TEST-01'
        $results | ForEach-Object { $_.ComputerName | Should -Be 'SVR-TEST-01' }
    }
}

Describe 'Copy-FirewallToGPO (Mocked)' {
    BeforeAll {
        $testRules = @(
            [PSCustomObject]@{
                ComputerName  = 'SVR-TEST-01'
                DisplayName   = 'Allow HTTP Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '80'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTP web traffic'
                PolicySource  = 'Local'
            },
            [PSCustomObject]@{
                ComputerName  = 'SVR-TEST-01'
                DisplayName   = 'Allow HTTPS Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '443'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTPS web traffic'
                PolicySource  = 'Local'
            },
            [PSCustomObject]@{
                ComputerName  = 'SVR-TEST-01'
                DisplayName   = 'Allow RDP Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '3389'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = '10.0.0.0/8'
                Program       = $null
                Profile       = 'Domain'
                Enabled       = $true
                Description   = 'Remote Desktop'
                PolicySource  = 'Local'
            }
        )
    }

    It 'Should call New-GPO when -CreateGPO is specified' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return $testRules }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-GPO { return $null }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-GPO { return [PSCustomObject]@{ DisplayName = 'Test-GPO'; Id = [guid]::NewGuid() } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-NetFirewallRule { }

        $result = Copy-FirewallToGPO -SourceComputer 'SVR-TEST-01' -GPOName 'Test-GPO' -CreateGPO -Confirm:$false

        Should -Invoke -CommandName 'New-GPO' -ModuleName 'LocalPolicy-ToGPO' -Times 1 -Exactly
    }

    It 'Should call New-NetFirewallRule for each rule' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return $testRules }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-GPO { return [PSCustomObject]@{ DisplayName = 'Test-GPO'; Id = [guid]::NewGuid() } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-NetFirewallRule { }

        $result = Copy-FirewallToGPO -SourceComputer 'SVR-TEST-01' -GPOName 'Test-GPO' -Confirm:$false

        Should -Invoke -CommandName 'New-NetFirewallRule' -ModuleName 'LocalPolicy-ToGPO' -Times 3 -Exactly
    }

    It 'Should use correct PolicyStore format for New-NetFirewallRule' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return @($testRules[0]) }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-GPO { return [PSCustomObject]@{ DisplayName = 'Test-GPO'; Id = [guid]::NewGuid() } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-NetFirewallRule -ParameterFilter {
            $PolicyStore -eq 'contoso.com\Test-GPO'
        } -MockWith { }

        $result = Copy-FirewallToGPO -SourceComputer 'SVR-TEST-01' -GPOName 'Test-GPO' -Confirm:$false

        Should -Invoke -CommandName 'New-NetFirewallRule' -ModuleName 'LocalPolicy-ToGPO' -Times 1 -Exactly -ParameterFilter {
            $PolicyStore -eq 'contoso.com\Test-GPO'
        }
    }

    It 'Should return a summary with correct migration count' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return $testRules }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-GPO { return [PSCustomObject]@{ DisplayName = 'Test-GPO'; Id = [guid]::NewGuid() } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-NetFirewallRule { }

        $result = Copy-FirewallToGPO -SourceComputer 'SVR-TEST-01' -GPOName 'Test-GPO' -Confirm:$false

        $result.RulesRead | Should -Be 3
        $result.RulesMigrated | Should -Be 3
        $result.RulesFailed | Should -Be 0
        $result.GPOName | Should -Be 'Test-GPO'
        $result.SourceComputer | Should -Be 'SVR-TEST-01'
    }

    It 'Should NOT call New-GPO when -CreateGPO is NOT specified and GPO exists' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return $testRules }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-GPO { return [PSCustomObject]@{ DisplayName = 'Test-GPO'; Id = [guid]::NewGuid() } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-GPO { }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-NetFirewallRule { }

        $result = Copy-FirewallToGPO -SourceComputer 'SVR-TEST-01' -GPOName 'Test-GPO' -Confirm:$false

        Should -Invoke -CommandName 'New-GPO' -ModuleName 'LocalPolicy-ToGPO' -Times 0 -Exactly
    }

    It 'Should handle rule creation failures gracefully' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return $testRules }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-GPO { return [PSCustomObject]@{ DisplayName = 'Test-GPO'; Id = [guid]::NewGuid() } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' New-NetFirewallRule { throw 'Rule creation failed' }

        $result = Copy-FirewallToGPO -SourceComputer 'SVR-TEST-01' -GPOName 'Test-GPO' -Confirm:$false -WarningAction SilentlyContinue

        $result.RulesRead | Should -Be 3
        $result.RulesMigrated | Should -Be 0
        $result.RulesFailed | Should -Be 3
    }
}

Describe 'Compare-PolicyCompliance (Mocked)' {
    BeforeAll {
        $localRules = @(
            [PSCustomObject]@{
                ComputerName  = 'SVR-TEST-01'
                DisplayName   = 'Allow HTTP Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '80'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTP web traffic'
                PolicySource  = 'Local'
            },
            [PSCustomObject]@{
                ComputerName  = 'SVR-TEST-01'
                DisplayName   = 'Allow HTTPS Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '443'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTPS web traffic'
                PolicySource  = 'Local'
            },
            [PSCustomObject]@{
                ComputerName  = 'SVR-TEST-01'
                DisplayName   = 'Local Only Rule'
                Direction     = 'Outbound'
                Action        = 'Block'
                Protocol      = 'TCP'
                LocalPort     = '445'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Private'
                Enabled       = $true
                Description   = 'Block SMB outbound'
                PolicySource  = 'Local'
            }
        )

        # GPO rules: match HTTP, mismatch HTTPS (different port), missing Local Only, extra GPO-only rule
        $mockGpoNetRules = @(
            # Matches HTTP exactly
            [PSCustomObject]@{
                DisplayName = 'Allow HTTP Inbound'
                Direction   = 1  # Inbound
                Action      = 2  # Allow
                Enabled     = 'True'
                Profile     = 'Any'
            },
            # Mismatches HTTPS -- different Action
            [PSCustomObject]@{
                DisplayName = 'Allow HTTPS Inbound'
                Direction   = 1  # Inbound
                Action      = 4  # Block (mismatch)
                Enabled     = 'True'
                Profile     = 'Any'
            },
            # Extra rule only in GPO
            [PSCustomObject]@{
                DisplayName = 'GPO Extra Rule'
                Direction   = 1
                Action      = 2
                Enabled     = 'True'
                Profile     = 'Domain'
            }
        )
    }

    It 'Should detect MATCH findings for identical rules' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return $localRules }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalSecurityPolicy { return @() }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-GPO { return [PSCustomObject]@{ DisplayName = 'Test-GPO'; Id = [guid]::NewGuid() } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallRule {
            return @(
                [PSCustomObject]@{
                    DisplayName = 'Allow HTTP Inbound'
                    Direction   = [PSCustomObject]@{ value__ = 1 }
                    Action      = [PSCustomObject]@{ value__ = 2 }
                    Enabled     = 'True'
                    Profile     = [PSCustomObject]@{ value__ = 0 }
                }
            )
        } -ModuleName 'LocalPolicy-ToGPO'
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallAddressFilter {
            return [PSCustomObject]@{ LocalAddress = 'Any'; RemoteAddress = 'Any' }
        }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallPortFilter {
            return [PSCustomObject]@{ Protocol = 'TCP'; LocalPort = '80'; RemotePort = 'Any' }
        }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallApplicationFilter {
            return [PSCustomObject]@{ Program = 'Any' }
        }
        Mock -ModuleName 'LocalPolicy-ToGPO' Test-Path { return $false } -ParameterFilter { $Path -like '*GptTmpl*' }

        $results = Compare-PolicyCompliance -ComputerName 'SVR-TEST-01' -GPOName 'Test-GPO' -CompareType Firewall

        $matchResults = $results | Where-Object { $_.Finding -eq 'MATCH' }
        $matchResults | Should -Not -BeNullOrEmpty
    }

    It 'Should detect MISSING FROM GPO findings' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return $localRules }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallRule { return @() } -ModuleName 'LocalPolicy-ToGPO'

        $results = Compare-PolicyCompliance -ComputerName 'SVR-TEST-01' -GPOName 'Test-GPO' -CompareType Firewall

        $missingResults = $results | Where-Object { $_.Finding -eq 'MISSING FROM GPO' }
        $missingResults.Count | Should -Be 3
    }

    It 'Should detect MISMATCH findings for differing rules' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy {
            return @([PSCustomObject]@{
                ComputerName  = 'SVR-TEST-01'
                DisplayName   = 'Allow HTTPS Inbound'
                Direction     = 'Inbound'
                Action        = 'Allow'
                Protocol      = 'TCP'
                LocalPort     = '443'
                RemotePort    = 'Any'
                LocalAddress  = 'Any'
                RemoteAddress = 'Any'
                Program       = $null
                Profile       = 'Any'
                Enabled       = $true
                Description   = 'HTTPS'
                PolicySource  = 'Local'
            })
        }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallRule {
            return @(
                [PSCustomObject]@{
                    DisplayName = 'Allow HTTPS Inbound'
                    Direction   = [PSCustomObject]@{ value__ = 1 }
                    Action      = [PSCustomObject]@{ value__ = 4 }
                    Enabled     = 'True'
                    Profile     = [PSCustomObject]@{ value__ = 0 }
                }
            )
        } -ModuleName 'LocalPolicy-ToGPO'
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallAddressFilter {
            return [PSCustomObject]@{ LocalAddress = 'Any'; RemoteAddress = 'Any' }
        }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallPortFilter {
            return [PSCustomObject]@{ Protocol = 'TCP'; LocalPort = '443'; RemotePort = 'Any' }
        }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallApplicationFilter {
            return [PSCustomObject]@{ Program = 'Any' }
        }

        $results = Compare-PolicyCompliance -ComputerName 'SVR-TEST-01' -GPOName 'Test-GPO' -CompareType Firewall

        $mismatchResults = $results | Where-Object { $_.Finding -like 'MISMATCH*' }
        $mismatchResults | Should -Not -BeNullOrEmpty
    }

    It 'Should return objects with expected properties' {
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-LocalFirewallPolicy { return @($localRules[0]) }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-ADDomain { return [PSCustomObject]@{ DNSRoot = 'contoso.com' } }
        Mock -ModuleName 'LocalPolicy-ToGPO' Get-NetFirewallRule { return @() } -ModuleName 'LocalPolicy-ToGPO'

        $results = Compare-PolicyCompliance -ComputerName 'SVR-TEST-01' -GPOName 'Test-GPO' -CompareType Firewall
        $result = $results | Select-Object -First 1

        $result.PSObject.Properties.Name | Should -Contain 'SettingName'
        $result.PSObject.Properties.Name | Should -Contain 'LocalValue'
        $result.PSObject.Properties.Name | Should -Contain 'GPOValue'
        $result.PSObject.Properties.Name | Should -Contain 'Match'
        $result.PSObject.Properties.Name | Should -Contain 'CompareType'
        $result.PSObject.Properties.Name | Should -Contain 'Finding'
    }
}
