function Get-LocalSecurityPolicy {
    <#
    .SYNOPSIS
        Reads local security policy settings from a server. Never modifies local policy.

    .DESCRIPTION
        Connects to one or more servers and exports the local security policy using
        secedit /export. Parses the resulting .inf file to extract settings from
        System Access, Event Audit, Privilege Rights, and Registry Values sections.

        This function is READ-ONLY. It never creates, modifies, or deletes any
        security policy setting on the source server. The only file it creates is a
        temporary .inf export that is removed after parsing.

    .PARAMETER ComputerName
        One or more server names to read security policy from. Defaults to localhost.

    .PARAMETER ExportPath
        Optional file path to save the structured results as JSON for review.

    .EXAMPLE
        Get-LocalSecurityPolicy -ComputerName "SVR-WEB-01" | Where-Object Category -eq 'AuditPolicy'

        Reads security policy from SVR-WEB-01 and filters to audit policy settings only.

    .EXAMPLE
        Get-LocalSecurityPolicy -ComputerName "SVR-WEB-01" -ExportPath .\secpol-export.json

        Reads all local security policy settings and saves them to JSON.

    .OUTPUTS
        PSCustomObject with properties: ComputerName, Category, SettingName, SettingValue, Description
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = @('localhost'),

        [Parameter()]
        [string]$ExportPath
    )

    begin {
        $allResults = [System.Collections.Generic.List[PSObject]]::new()
        Write-Verbose "Get-LocalSecurityPolicy: READ-ONLY operation -- no local policy will be modified."

        # Category mapping from .inf section headers to friendly names
        $sectionMap = @{
            'System Access'   = 'SystemAccess'
            'Event Audit'     = 'AuditPolicy'
            'Privilege Rights' = 'UserRights'
            'Registry Values' = 'SecurityOptions'
        }

        # Friendly descriptions for common security settings
        $settingDescriptions = @{
            # System Access
            'MinimumPasswordAge'          = 'Minimum password age (days)'
            'MaximumPasswordAge'          = 'Maximum password age (days)'
            'MinimumPasswordLength'       = 'Minimum password length (characters)'
            'PasswordComplexity'          = 'Password must meet complexity requirements'
            'PasswordHistorySize'         = 'Enforce password history (passwords remembered)'
            'LockoutBadCount'             = 'Account lockout threshold (invalid attempts)'
            'ResetLockoutCount'           = 'Reset account lockout counter after (minutes)'
            'LockoutDuration'             = 'Account lockout duration (minutes)'
            'ForceLogoffWhenHourExpire'   = 'Force logoff when logon hours expire'
            'NewAdministratorName'        = 'Rename administrator account'
            'NewGuestName'                = 'Rename guest account'
            'ClearTextPassword'           = 'Store passwords using reversible encryption'
            'LSAAnonymousNameLookup'      = 'Allow anonymous SID/Name translation'
            'EnableAdminAccount'          = 'Enable Administrator account'
            'EnableGuestAccount'          = 'Enable Guest account'
            # Audit Policy
            'AuditSystemEvents'           = 'Audit system events'
            'AuditLogonEvents'            = 'Audit logon events'
            'AuditObjectAccess'           = 'Audit object access'
            'AuditPrivilegeUse'           = 'Audit privilege use'
            'AuditPolicyChange'           = 'Audit policy change'
            'AuditAccountManage'          = 'Audit account management'
            'AuditProcessTracking'        = 'Audit process tracking'
            'AuditDSAccess'               = 'Audit directory service access'
            'AuditAccountLogon'           = 'Audit account logon events'
            # User Rights
            'SeNetworkLogonRight'         = 'Access this computer from the network'
            'SeDenyNetworkLogonRight'     = 'Deny access to this computer from the network'
            'SeInteractiveLogonRight'     = 'Allow log on locally'
            'SeDenyInteractiveLogonRight' = 'Deny log on locally'
            'SeRemoteInteractiveLogonRight' = 'Allow log on through Remote Desktop'
            'SeDenyRemoteInteractiveLogonRight' = 'Deny log on through Remote Desktop'
            'SeBackupPrivilege'           = 'Back up files and directories'
            'SeRestorePrivilege'          = 'Restore files and directories'
            'SeShutdownPrivilege'         = 'Shut down the system'
            'SeBatchLogonRight'           = 'Log on as a batch job'
            'SeServiceLogonRight'         = 'Log on as a service'
            'SeDebugPrivilege'            = 'Debug programs'
            'SeTakeOwnershipPrivilege'    = 'Take ownership of files or other objects'
            'SeManageVolumePrivilege'     = 'Perform volume maintenance tasks'
        }

        $scriptBlock = {
            # Export local security policy to a temp .inf file using secedit
            $tempInf = Join-Path $env:TEMP "secpol_export_$(Get-Random).inf"
            try {
                $seceditOutput = & secedit /export /cfg $tempInf 2>&1
                if (-not (Test-Path $tempInf)) {
                    throw "secedit export failed: $seceditOutput"
                }
                # Read and return the raw .inf content
                Get-Content -Path $tempInf -Raw
            }
            finally {
                # Clean up temp file
                if (Test-Path $tempInf) {
                    Remove-Item -Path $tempInf -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Reading local security policy from '$computer'..."

            try {
                if ($computer -eq 'localhost' -or $computer -eq $env:COMPUTERNAME -or $computer -eq '.') {
                    Write-Verbose "Executing locally on '$computer'."
                    $infContent = & $scriptBlock
                }
                else {
                    Write-Verbose "Executing remotely on '$computer' via Invoke-Command."
                    $infContent = Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ErrorAction Stop
                }

                if (-not $infContent) {
                    Write-Warning "No security policy content retrieved from '$computer'."
                    continue
                }

                # Parse the .inf file content
                $currentSection = $null
                $lines = $infContent -split "`r?`n"

                foreach ($line in $lines) {
                    $trimmed = $line.Trim()

                    # Skip empty lines and comments
                    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith(';')) {
                        continue
                    }

                    # Check for section headers
                    if ($trimmed -match '^\[(.+)\]$') {
                        $currentSection = $Matches[1]
                        continue
                    }

                    # Only parse sections we care about
                    if ($currentSection -and $sectionMap.ContainsKey($currentSection)) {
                        $category = $sectionMap[$currentSection]

                        # Parse key = value pairs
                        if ($trimmed -match '^(.+?)\s*=\s*(.*)$') {
                            $settingName  = $Matches[1].Trim()
                            $settingValue = $Matches[2].Trim()

                            # Look up description
                            $description = if ($settingDescriptions.ContainsKey($settingName)) {
                                $settingDescriptions[$settingName]
                            }
                            else {
                                $settingName
                            }

                            $obj = [PSCustomObject]@{
                                ComputerName = $computer
                                Category     = $category
                                SettingName  = $settingName
                                SettingValue = $settingValue
                                Description  = $description
                            }

                            $allResults.Add($obj)
                            $obj
                        }
                    }
                }

                Write-Verbose "Parsed $($allResults.Count) security policy setting(s) from '$computer'."
            }
            catch {
                Write-Error "Failed to read security policy from '$computer': $_"
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
                Write-Verbose "Exported $($allResults.Count) setting(s) to '$ExportPath'."
                Write-Output "Export saved to: $ExportPath"
            }
            catch {
                Write-Error "Failed to export results to '$ExportPath': $_"
            }
        }
    }
}
