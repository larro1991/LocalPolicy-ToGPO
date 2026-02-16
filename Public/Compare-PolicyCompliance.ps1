function Compare-PolicyCompliance {
    <#
    .SYNOPSIS
        Compares local policy on a server against a GPO to verify migration completeness.

    .DESCRIPTION
        After migrating local policy settings to a GPO with Copy-FirewallToGPO or
        Copy-SecurityPolicyToGPO, use this function to verify the migration was
        complete and accurate.

        For firewall rules, the comparison matches rules by DisplayName and compares
        Direction, Action, Protocol, LocalPort, RemotePort, LocalAddress, RemoteAddress,
        Program, and Profile properties.

        For security policy, the comparison matches settings by SettingName and compares
        values.

        Findings are classified as: MATCH, MISMATCH (with detail on what differs),
        MISSING FROM GPO, or EXTRA IN GPO.

        This function is READ-ONLY on both the local server and the GPO.

    .PARAMETER ComputerName
        The server to compare local policy from.

    .PARAMETER GPOName
        The GPO to compare against.

    .PARAMETER CompareType
        What to compare. Valid values: Firewall, SecurityPolicy, Both. Defaults to Both.

    .PARAMETER OutputPath
        Optional file path to save an HTML compliance report.

    .EXAMPLE
        Compare-PolicyCompliance -ComputerName "SVR-WEB-01" -GPOName "Firewall-WebServers"

        Compares both firewall and security policy between the local server and GPO.

    .EXAMPLE
        Compare-PolicyCompliance -ComputerName "SVR-WEB-01" -GPOName "Firewall-WebServers" -CompareType Firewall -OutputPath .\compliance.html

        Compares only firewall rules and generates an HTML report.

    .OUTPUTS
        PSCustomObject with properties: SettingName, LocalValue, GPOValue, Match, CompareType, Finding
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$GPOName,

        [Parameter()]
        [ValidateSet('Firewall', 'SecurityPolicy', 'Both')]
        [string]$CompareType = 'Both',

        [Parameter()]
        [string]$OutputPath
    )

    begin {
        $results = [System.Collections.Generic.List[PSObject]]::new()
        Write-Verbose "Compare-PolicyCompliance: READ-ONLY comparison -- no policy will be modified."
    }

    process {
        # ==================================================================
        # Firewall comparison
        # ==================================================================
        if ($CompareType -eq 'Firewall' -or $CompareType -eq 'Both') {
            Write-Verbose "Comparing firewall rules between '$ComputerName' (local) and GPO '$GPOName'..."

            # Read local firewall rules
            $localRules = Get-LocalFirewallPolicy -ComputerName $ComputerName -ErrorAction Stop

            # Read GPO firewall rules
            $gpoRules = @()
            try {
                $domainName = $null
                try {
                    $domainName = (Get-ADDomain -ErrorAction Stop).DNSRoot
                }
                catch {
                    $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                }

                $policyStore = "$domainName\$GPOName"
                $gpoNetRules = Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction Stop

                foreach ($rule in $gpoNetRules) {
                    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                    $portFilter    = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                    $appFilter     = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue

                    $gpoRules += [PSCustomObject]@{
                        DisplayName   = $rule.DisplayName
                        Direction     = $rule.Direction.ToString()
                        Action        = $rule.Action.ToString()
                        Protocol      = if ($portFilter) { $portFilter.Protocol } else { 'Any' }
                        LocalPort     = if ($portFilter) { $portFilter.LocalPort } else { 'Any' }
                        RemotePort    = if ($portFilter) { $portFilter.RemotePort } else { 'Any' }
                        LocalAddress  = if ($addressFilter) { $addressFilter.LocalAddress } else { 'Any' }
                        RemoteAddress = if ($addressFilter) { $addressFilter.RemoteAddress } else { 'Any' }
                        Program       = if ($appFilter -and $appFilter.Program -ne 'Any') { $appFilter.Program } else { $null }
                        Profile       = $rule.Profile.ToString()
                        Enabled       = ($rule.Enabled -eq 'True')
                    }
                }
            }
            catch {
                Write-Error "Failed to read GPO firewall rules from '$GPOName': $_"
            }

            Write-Verbose "Local: $($localRules.Count) rule(s), GPO: $($gpoRules.Count) rule(s)"

            # Build lookup of GPO rules by DisplayName
            $gpoRuleLookup = @{}
            foreach ($gpoRule in $gpoRules) {
                $gpoRuleLookup[$gpoRule.DisplayName] = $gpoRule
            }

            $localRuleLookup = @{}
            foreach ($localRule in $localRules) {
                $localRuleLookup[$localRule.DisplayName] = $localRule
            }

            # Compare properties of interest
            $compareProperties = @('Direction', 'Action', 'Protocol', 'LocalPort', 'RemotePort',
                                   'LocalAddress', 'RemoteAddress', 'Program', 'Profile')

            # Check each local rule against GPO
            foreach ($localRule in $localRules) {
                $name = $localRule.DisplayName

                if ($gpoRuleLookup.ContainsKey($name)) {
                    $gpoRule = $gpoRuleLookup[$name]
                    $mismatches = [System.Collections.Generic.List[string]]::new()

                    foreach ($prop in $compareProperties) {
                        $localVal = if ($null -ne $localRule.$prop) { "$($localRule.$prop)" } else { '' }
                        $gpoVal   = if ($null -ne $gpoRule.$prop)   { "$($gpoRule.$prop)" }   else { '' }

                        if ($localVal -ne $gpoVal) {
                            $mismatches.Add("$prop`: Local='$localVal' GPO='$gpoVal'")
                        }
                    }

                    if ($mismatches.Count -eq 0) {
                        $results.Add([PSCustomObject]@{
                            SettingName = $name
                            LocalValue  = "Inbound=$($localRule.Direction) Action=$($localRule.Action) Port=$($localRule.LocalPort)"
                            GPOValue    = "Inbound=$($gpoRule.Direction) Action=$($gpoRule.Action) Port=$($gpoRule.LocalPort)"
                            Match       = $true
                            CompareType = 'Firewall'
                            Finding     = 'MATCH'
                        })
                    }
                    else {
                        $results.Add([PSCustomObject]@{
                            SettingName = $name
                            LocalValue  = "Inbound=$($localRule.Direction) Action=$($localRule.Action) Port=$($localRule.LocalPort)"
                            GPOValue    = "Inbound=$($gpoRule.Direction) Action=$($gpoRule.Action) Port=$($gpoRule.LocalPort)"
                            Match       = $false
                            CompareType = 'Firewall'
                            Finding     = "MISMATCH: $($mismatches -join '; ')"
                        })
                    }
                }
                else {
                    $results.Add([PSCustomObject]@{
                        SettingName = $name
                        LocalValue  = "Inbound=$($localRule.Direction) Action=$($localRule.Action) Port=$($localRule.LocalPort)"
                        GPOValue    = 'N/A'
                        Match       = $false
                        CompareType = 'Firewall'
                        Finding     = 'MISSING FROM GPO'
                    })
                }
            }

            # Check for GPO rules not in local (extra)
            foreach ($gpoRule in $gpoRules) {
                if (-not $localRuleLookup.ContainsKey($gpoRule.DisplayName)) {
                    $results.Add([PSCustomObject]@{
                        SettingName = $gpoRule.DisplayName
                        LocalValue  = 'N/A'
                        GPOValue    = "Inbound=$($gpoRule.Direction) Action=$($gpoRule.Action) Port=$($gpoRule.LocalPort)"
                        Match       = $false
                        CompareType = 'Firewall'
                        Finding     = 'EXTRA IN GPO'
                    })
                }
            }
        }

        # ==================================================================
        # Security Policy comparison
        # ==================================================================
        if ($CompareType -eq 'SecurityPolicy' -or $CompareType -eq 'Both') {
            Write-Verbose "Comparing security policy between '$ComputerName' (local) and GPO '$GPOName'..."

            # Read local security policy
            $localSettings = Get-LocalSecurityPolicy -ComputerName $ComputerName -ErrorAction Stop

            # Read GPO security policy from GptTmpl.inf
            $gpoSettings = @()
            try {
                $domainName = $null
                try {
                    $domainName = (Get-ADDomain -ErrorAction Stop).DNSRoot
                }
                catch {
                    $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                }

                $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
                $gpoId = $gpo.Id.ToString('B').ToUpper()
                $infPath = "\\$domainName\SYSVOL\$domainName\Policies\$gpoId\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                if (Test-Path $infPath) {
                    $infContent = Get-Content -Path $infPath -Raw

                    $sectionMap = @{
                        'System Access'    = 'SystemAccess'
                        'Event Audit'      = 'AuditPolicy'
                        'Privilege Rights' = 'UserRights'
                        'Registry Values'  = 'SecurityOptions'
                    }

                    $currentSection = $null
                    $lines = $infContent -split "`r?`n"

                    foreach ($line in $lines) {
                        $trimmed = $line.Trim()
                        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith(';')) { continue }

                        if ($trimmed -match '^\[(.+)\]$') {
                            $currentSection = $Matches[1]
                            continue
                        }

                        if ($currentSection -and $sectionMap.ContainsKey($currentSection)) {
                            if ($trimmed -match '^(.+?)\s*=\s*(.*)$') {
                                $gpoSettings += [PSCustomObject]@{
                                    Category     = $sectionMap[$currentSection]
                                    SettingName  = $Matches[1].Trim()
                                    SettingValue = $Matches[2].Trim()
                                }
                            }
                        }
                    }
                }
                else {
                    Write-Verbose "No GptTmpl.inf found in GPO '$GPOName'. GPO may not have security settings."
                }
            }
            catch {
                Write-Error "Failed to read GPO security policy from '$GPOName': $_"
            }

            Write-Verbose "Local: $($localSettings.Count) setting(s), GPO: $($gpoSettings.Count) setting(s)"

            # Build lookup of GPO settings by name
            $gpoSettingLookup = @{}
            foreach ($gpoSetting in $gpoSettings) {
                $gpoSettingLookup[$gpoSetting.SettingName] = $gpoSetting
            }

            $localSettingLookup = @{}
            foreach ($localSetting in $localSettings) {
                $localSettingLookup[$localSetting.SettingName] = $localSetting
            }

            # Compare each local setting against GPO
            foreach ($localSetting in $localSettings) {
                $name = $localSetting.SettingName

                if ($gpoSettingLookup.ContainsKey($name)) {
                    $gpoSetting = $gpoSettingLookup[$name]

                    if ($localSetting.SettingValue -eq $gpoSetting.SettingValue) {
                        $results.Add([PSCustomObject]@{
                            SettingName = $name
                            LocalValue  = $localSetting.SettingValue
                            GPOValue    = $gpoSetting.SettingValue
                            Match       = $true
                            CompareType = 'SecurityPolicy'
                            Finding     = 'MATCH'
                        })
                    }
                    else {
                        $results.Add([PSCustomObject]@{
                            SettingName = $name
                            LocalValue  = $localSetting.SettingValue
                            GPOValue    = $gpoSetting.SettingValue
                            Match       = $false
                            CompareType = 'SecurityPolicy'
                            Finding     = "MISMATCH: Local='$($localSetting.SettingValue)' GPO='$($gpoSetting.SettingValue)'"
                        })
                    }
                }
                else {
                    $results.Add([PSCustomObject]@{
                        SettingName = $name
                        LocalValue  = $localSetting.SettingValue
                        GPOValue    = 'N/A'
                        Match       = $false
                        CompareType = 'SecurityPolicy'
                        Finding     = 'MISSING FROM GPO'
                    })
                }
            }

            # Check for GPO settings not in local
            foreach ($gpoSetting in $gpoSettings) {
                if (-not $localSettingLookup.ContainsKey($gpoSetting.SettingName)) {
                    $results.Add([PSCustomObject]@{
                        SettingName = $gpoSetting.SettingName
                        LocalValue  = 'N/A'
                        GPOValue    = $gpoSetting.SettingValue
                        Match       = $false
                        CompareType = 'SecurityPolicy'
                        Finding     = 'EXTRA IN GPO'
                    })
                }
            }
        }

        # Output results
        $results
    }

    end {
        # ------------------------------------------------------------------
        # Generate HTML report if requested
        # ------------------------------------------------------------------
        if ($OutputPath -and $results.Count -gt 0) {
            Write-Verbose "Generating HTML compliance report..."

            try {
                $totalCount    = $results.Count
                $matchCount    = ($results | Where-Object { $_.Finding -eq 'MATCH' }).Count
                $mismatchCount = ($results | Where-Object { $_.Finding -like 'MISMATCH*' }).Count
                $missingCount  = ($results | Where-Object { $_.Finding -eq 'MISSING FROM GPO' }).Count
                $extraCount    = ($results | Where-Object { $_.Finding -eq 'EXTRA IN GPO' }).Count

                $html = New-HtmlDashboard -Title "Policy Compliance: $ComputerName vs GPO '$GPOName'" `
                    -GeneratedDate (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `
                    -SummaryCards @(
                        @{ Label = 'Total Settings'; Value = $totalCount;    Color = '#56d4dd' }
                        @{ Label = 'Matched';        Value = $matchCount;    Color = '#4caf50' }
                        @{ Label = 'Mismatched';     Value = $mismatchCount; Color = '#f44336' }
                        @{ Label = 'Missing from GPO'; Value = $missingCount; Color = '#ff9800' }
                        @{ Label = 'Extra in GPO';   Value = $extraCount;    Color = '#9c27b0' }
                    ) `
                    -Sections @(
                        @{
                            Title   = 'Compliance Details'
                            Content = $results
                            Type    = 'Table'
                        }
                    ) `
                    -Findings $results

                $outDir = Split-Path -Path $OutputPath -Parent
                if ($outDir -and -not (Test-Path $outDir)) {
                    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
                }

                Set-Content -Path $OutputPath -Value $html -Encoding UTF8
                Write-Verbose "HTML report saved to '$OutputPath'."
                Write-Output "Compliance report saved to: $OutputPath"
            }
            catch {
                Write-Error "Failed to generate HTML report: $_"
            }
        }

        Write-Verbose "Comparison complete: $($results.Count) total finding(s)."
    }
}
