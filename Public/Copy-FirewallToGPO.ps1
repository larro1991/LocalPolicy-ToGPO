function Copy-FirewallToGPO {
    <#
    .SYNOPSIS
        Copies local firewall rules into a domain GPO. Writes to GPO only, never touches local policy.

    .DESCRIPTION
        Reads firewall rules from a source server using Get-LocalFirewallPolicy, then
        creates equivalent rules in a domain GPO using New-NetFirewallRule with
        the -PolicyStore parameter targeting the GPO.

        This function ONLY WRITES to the specified GPO. It NEVER modifies, deletes,
        or changes any local firewall rule on the source server. The source is read-only.

        Every New-NetFirewallRule call supports -WhatIf so you can preview the migration
        before committing. Rule descriptions are prefixed with migration metadata for
        audit trail purposes.

    .PARAMETER SourceComputer
        The server to read local firewall rules from.

    .PARAMETER GPOName
        Name of the GPO to create the firewall rules in. If -CreateGPO is specified and
        GPOName is not provided, the name defaults to "Firewall - ServerName - Migrated YYYY-MM-DD".

    .PARAMETER CreateGPO
        If specified, creates the GPO if it does not already exist.

    .PARAMETER ProfileFilter
        Filter source rules by firewall profile. Valid values: Domain, Private, Public, Any.
        Defaults to Any.

    .PARAMETER EnabledOnly
        When specified (default), only migrates rules that are currently enabled.

    .PARAMETER WhatIf
        Shows what would happen without making any changes.

    .PARAMETER Confirm
        Prompts for confirmation before each rule is created in the GPO.

    .EXAMPLE
        Copy-FirewallToGPO -SourceComputer "SVR-WEB-01" -GPOName "Firewall-WebServers" -CreateGPO -WhatIf

        Previews the migration of all local firewall rules from SVR-WEB-01 into a new GPO.

    .EXAMPLE
        Copy-FirewallToGPO -SourceComputer "SVR-WEB-01" -GPOName "Firewall-WebServers" -CreateGPO -ProfileFilter Domain

        Migrates only Domain-profile firewall rules from SVR-WEB-01 into the GPO.

    .OUTPUTS
        PSCustomObject with properties: SourceComputer, GPOName, RulesRead, RulesMigrated, RulesFailed, Timestamp
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceComputer,

        [Parameter(Mandatory = $true)]
        [string]$GPOName,

        [Parameter()]
        [switch]$CreateGPO,

        [Parameter()]
        [ValidateSet('Domain', 'Private', 'Public', 'Any')]
        [string]$ProfileFilter = 'Any',

        [Parameter()]
        [switch]$EnabledOnly = $true
    )

    begin {
        Write-Verbose "Copy-FirewallToGPO: READ from '$SourceComputer', WRITE to GPO '$GPOName'."
        Write-Verbose "Local policy on '$SourceComputer' will NOT be modified."

        $timestamp    = Get-Date -Format 'yyyy-MM-dd'
        $rulesMigrated = 0
        $rulesFailed   = 0
    }

    process {
        # ------------------------------------------------------------------
        # Step 1: Read local firewall rules from the source server
        # ------------------------------------------------------------------
        Write-Verbose "Step 1: Reading local firewall rules from '$SourceComputer'..."
        $getParams = @{
            ComputerName  = $SourceComputer
            ProfileFilter = $ProfileFilter
            EnabledOnly   = $EnabledOnly
        }
        $rules = Get-LocalFirewallPolicy @getParams
        $rulesRead = ($rules | Measure-Object).Count

        if ($rulesRead -eq 0) {
            Write-Warning "No local firewall rules found on '$SourceComputer' matching the specified criteria. Nothing to migrate."
            return [PSCustomObject]@{
                SourceComputer = $SourceComputer
                GPOName        = $GPOName
                RulesRead      = 0
                RulesMigrated  = 0
                RulesFailed    = 0
                Timestamp      = $timestamp
            }
        }

        Write-Verbose "Found $rulesRead local firewall rule(s) to migrate."

        # ------------------------------------------------------------------
        # Step 2: Create or validate the GPO
        # ------------------------------------------------------------------
        Write-Verbose "Step 2: Preparing target GPO '$GPOName'..."

        $gpo = $null
        try {
            $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        }
        catch {
            # GPO does not exist
        }

        if (-not $gpo) {
            if ($CreateGPO) {
                if ($PSCmdlet.ShouldProcess($GPOName, 'Create new Group Policy Object')) {
                    try {
                        $gpo = New-GPO -Name $GPOName -Comment "Firewall rules migrated from $SourceComputer on $timestamp. Created by LocalPolicy-ToGPO module." -ErrorAction Stop
                        Write-Verbose "Created GPO '$GPOName'."
                    }
                    catch {
                        Write-Error "Failed to create GPO '$GPOName': $_"
                        return
                    }
                }
            }
            else {
                Write-Error "GPO '$GPOName' does not exist. Use -CreateGPO to create it automatically."
                return
            }
        }
        else {
            Write-Verbose "GPO '$GPOName' already exists."
        }

        # ------------------------------------------------------------------
        # Step 3: Determine the PolicyStore path for the GPO
        # ------------------------------------------------------------------
        $domainName = $null
        try {
            $domainName = (Get-ADDomain -ErrorAction Stop).DNSRoot
        }
        catch {
            try {
                $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            }
            catch {
                Write-Error "Unable to determine domain name. Ensure the computer is domain-joined and AD modules are available."
                return
            }
        }

        $policyStore = "$domainName\$GPOName"
        Write-Verbose "PolicyStore target: '$policyStore'"

        # ------------------------------------------------------------------
        # Step 4: Create each firewall rule in the GPO
        # ------------------------------------------------------------------
        Write-Verbose "Step 4: Migrating firewall rules to GPO..."

        foreach ($rule in $rules) {
            $migrationDesc = "[Migrated from $SourceComputer on $timestamp] $($rule.Description)"

            $ruleParams = @{
                PolicyStore  = $policyStore
                DisplayName  = $rule.DisplayName
                Direction    = $rule.Direction
                Action       = $rule.Action
                Profile      = $rule.Profile
                Enabled      = if ($rule.Enabled) { 'True' } else { 'False' }
                Description  = $migrationDesc
                ErrorAction  = 'Stop'
            }

            # Add optional parameters only when meaningful values exist
            if ($rule.Protocol -and $rule.Protocol -ne 'Any') {
                $ruleParams['Protocol'] = $rule.Protocol
            }
            if ($rule.LocalPort -and $rule.LocalPort -ne 'Any') {
                $ruleParams['LocalPort'] = $rule.LocalPort
            }
            if ($rule.RemotePort -and $rule.RemotePort -ne 'Any') {
                $ruleParams['RemotePort'] = $rule.RemotePort
            }
            if ($rule.LocalAddress -and $rule.LocalAddress -ne 'Any') {
                $ruleParams['LocalAddress'] = $rule.LocalAddress
            }
            if ($rule.RemoteAddress -and $rule.RemoteAddress -ne 'Any') {
                $ruleParams['RemoteAddress'] = $rule.RemoteAddress
            }
            if ($rule.Program) {
                $ruleParams['Program'] = $rule.Program
            }

            $whatIfMessage = "Create firewall rule '$($rule.DisplayName)' ($($rule.Direction)/$($rule.Action)) in GPO '$GPOName'"

            if ($PSCmdlet.ShouldProcess($whatIfMessage, 'New-NetFirewallRule')) {
                try {
                    New-NetFirewallRule @ruleParams | Out-Null
                    $rulesMigrated++
                    Write-Verbose "Migrated: $($rule.DisplayName) ($($rule.Direction)/$($rule.Action)/$($rule.Protocol):$($rule.LocalPort))"
                }
                catch {
                    $rulesFailed++
                    Write-Warning "Failed to migrate rule '$($rule.DisplayName)': $_"
                }
            }
        }
    }

    end {
        $summary = [PSCustomObject]@{
            SourceComputer = $SourceComputer
            GPOName        = $GPOName
            RulesRead      = $rulesRead
            RulesMigrated  = $rulesMigrated
            RulesFailed    = $rulesFailed
            Timestamp      = $timestamp
        }

        Write-Verbose "Migration complete: $rulesRead read, $rulesMigrated migrated, $rulesFailed failed."
        $summary
    }
}
