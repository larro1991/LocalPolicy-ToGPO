function Get-LocalFirewallPolicy {
    <#
    .SYNOPSIS
        Reads local firewall rules from a server. Never modifies local policy.

    .DESCRIPTION
        Connects to one or more servers and reads their locally configured Windows
        Firewall rules. Rules delivered by Group Policy are automatically excluded
        so only manually configured local rules are returned.

        This function is READ-ONLY. It never creates, modifies, or deletes any
        firewall rule on the source server.

        For each rule the function also retrieves address filters, port filters,
        and application filters to provide full rule detail.

    .PARAMETER ComputerName
        One or more server names to read firewall rules from. Defaults to localhost.
        Accepts pipeline input.

    .PARAMETER ProfileFilter
        Filter rules by firewall profile. Valid values: Domain, Private, Public, Any.
        Defaults to Any (all profiles).

    .PARAMETER EnabledOnly
        When specified (default), only returns rules that are currently enabled.
        Use -EnabledOnly:$false to include disabled rules.

    .PARAMETER ExportPath
        Optional file path to save the results as JSON for review before migration.

    .EXAMPLE
        Get-LocalFirewallPolicy -ComputerName "SVR-WEB-01" -ExportPath .\firewall-export.json

        Reads all enabled local firewall rules from SVR-WEB-01 and saves them to JSON.

    .EXAMPLE
        Get-LocalFirewallPolicy -ComputerName "SVR-WEB-01","SVR-WEB-02" -ProfileFilter Domain

        Reads only Domain-profile firewall rules from two servers.

    .EXAMPLE
        "SVR-WEB-01","SVR-WEB-02" | Get-LocalFirewallPolicy -EnabledOnly:$false

        Reads all local firewall rules (including disabled) from servers via pipeline.

    .OUTPUTS
        PSCustomObject with properties: ComputerName, DisplayName, Direction, Action,
        Protocol, LocalPort, RemotePort, LocalAddress, RemoteAddress, Program, Profile,
        Enabled, Description, PolicySource
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = @('localhost'),

        [Parameter()]
        [ValidateSet('Domain', 'Private', 'Public', 'Any')]
        [string]$ProfileFilter = 'Any',

        [Parameter()]
        [switch]$EnabledOnly = $true,

        [Parameter()]
        [string]$ExportPath
    )

    begin {
        $allResults = [System.Collections.Generic.List[PSObject]]::new()
        Write-Verbose "Get-LocalFirewallPolicy: READ-ONLY operation -- no local policy will be modified."
    }

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Reading local firewall rules from '$computer'..."

            $scriptBlock = {
                param($ProfileFilter, $EnabledOnly)

                # Get all local firewall rules -- exclude GPO-delivered rules
                $rules = Get-NetFirewallRule | Where-Object {
                    $_.PolicyStoreSourceType -ne 'GroupPolicy'
                }

                # Filter by enabled state
                if ($EnabledOnly) {
                    $rules = $rules | Where-Object { $_.Enabled -eq 'True' }
                }

                # Filter by profile if not Any
                if ($ProfileFilter -ne 'Any') {
                    $rules = $rules | Where-Object {
                        $_.Profile -match $ProfileFilter -or $_.Profile -eq 'Any'
                    }
                }

                foreach ($rule in $rules) {
                    # Retrieve associated filters for full detail
                    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                    $portFilter    = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                    $appFilter     = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue

                    [PSCustomObject]@{
                        DisplayName  = $rule.DisplayName
                        Direction    = $rule.Direction.ToString()
                        Action       = $rule.Action.ToString()
                        Protocol     = if ($portFilter) { $portFilter.Protocol } else { 'Any' }
                        LocalPort    = if ($portFilter) { $portFilter.LocalPort } else { 'Any' }
                        RemotePort   = if ($portFilter) { $portFilter.RemotePort } else { 'Any' }
                        LocalAddress = if ($addressFilter) { $addressFilter.LocalAddress } else { 'Any' }
                        RemoteAddress= if ($addressFilter) { $addressFilter.RemoteAddress } else { 'Any' }
                        Program      = if ($appFilter -and $appFilter.Program -ne 'Any') { $appFilter.Program } else { $null }
                        Profile      = $rule.Profile.ToString()
                        Enabled      = ($rule.Enabled -eq 'True')
                        Description  = $rule.Description
                        PolicySource = 'Local'
                    }
                }
            }

            try {
                if ($computer -eq 'localhost' -or $computer -eq $env:COMPUTERNAME -or $computer -eq '.') {
                    Write-Verbose "Executing locally on '$computer'."
                    $results = & $scriptBlock -ProfileFilter $ProfileFilter -EnabledOnly $EnabledOnly
                }
                else {
                    Write-Verbose "Executing remotely on '$computer' via Invoke-Command."
                    $results = Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock `
                        -ArgumentList $ProfileFilter, $EnabledOnly -ErrorAction Stop
                }

                if ($results) {
                    foreach ($result in $results) {
                        # Add the source computer name
                        $obj = [PSCustomObject]@{
                            ComputerName  = $computer
                            DisplayName   = $result.DisplayName
                            Direction     = $result.Direction
                            Action        = $result.Action
                            Protocol      = $result.Protocol
                            LocalPort     = $result.LocalPort
                            RemotePort    = $result.RemotePort
                            LocalAddress  = $result.LocalAddress
                            RemoteAddress = $result.RemoteAddress
                            Program       = $result.Program
                            Profile       = $result.Profile
                            Enabled       = $result.Enabled
                            Description   = $result.Description
                            PolicySource  = $result.PolicySource
                        }
                        $allResults.Add($obj)
                        $obj
                    }
                    Write-Verbose "Retrieved $($results.Count) local firewall rule(s) from '$computer'."
                }
                else {
                    Write-Verbose "No local firewall rules found on '$computer' matching the specified criteria."
                }
            }
            catch {
                Write-Error "Failed to read firewall rules from '$computer': $_"
            }
        }
    }

    end {
        if ($ExportPath -and $allResults.Count -gt 0) {
            try {
                $exportDir = Split-Path -Path $ExportPath -Parent
                if ($exportDir -and -not (Test-Path $exportDir)) {
                    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                }
                $allResults | ConvertTo-Json -Depth 10 | Set-Content -Path $ExportPath -Encoding UTF8
                Write-Verbose "Exported $($allResults.Count) rule(s) to '$ExportPath'."
                Write-Output "Export saved to: $ExportPath"
            }
            catch {
                Write-Error "Failed to export results to '$ExportPath': $_"
            }
        }
    }
}
