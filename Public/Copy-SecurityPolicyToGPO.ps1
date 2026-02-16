function Copy-SecurityPolicyToGPO {
    <#
    .SYNOPSIS
        Copies local security policy settings into a domain GPO. Writes to GPO only, never touches local policy.

    .DESCRIPTION
        Reads security policy settings from a source server using Get-LocalSecurityPolicy,
        then generates a GptTmpl.inf file and copies it into the GPO's SYSVOL path. This
        effectively applies the local security settings to the GPO.

        This function ONLY WRITES to the specified GPO. It NEVER modifies, deletes,
        or changes any local security policy setting on the source server.

        All write operations support -WhatIf so you can preview the migration.

    .PARAMETER SourceComputer
        The server to read local security policy from.

    .PARAMETER GPOName
        Name of the GPO to write the security policy settings into.

    .PARAMETER CreateGPO
        If specified, creates the GPO if it does not already exist.

    .PARAMETER Categories
        Which security policy categories to migrate. Valid values:
        SystemAccess, AuditPolicy, UserRights, SecurityOptions, All.
        Defaults to All.

    .PARAMETER WhatIf
        Shows what would happen without making any changes.

    .PARAMETER Confirm
        Prompts for confirmation before writing to the GPO.

    .EXAMPLE
        Copy-SecurityPolicyToGPO -SourceComputer "SVR-WEB-01" -GPOName "Security-WebServers" -Categories AuditPolicy,UserRights -CreateGPO

        Migrates audit policy and user rights settings from SVR-WEB-01 into a new GPO.

    .EXAMPLE
        Copy-SecurityPolicyToGPO -SourceComputer "SVR-WEB-01" -GPOName "Security-WebServers" -CreateGPO -WhatIf

        Previews the migration of all security policy categories.

    .OUTPUTS
        PSCustomObject with properties: SourceComputer, GPOName, SettingsRead, SettingsMigrated, Categories, Timestamp
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
        [ValidateSet('SystemAccess', 'AuditPolicy', 'UserRights', 'SecurityOptions', 'All')]
        [string[]]$Categories = @('All'),

        [Parameter()]
        [switch]$Force
    )

    begin {
        Write-Verbose "Copy-SecurityPolicyToGPO: READ from '$SourceComputer', WRITE to GPO '$GPOName'."
        Write-Verbose "Local policy on '$SourceComputer' will NOT be modified."

        $timestamp        = Get-Date -Format 'yyyy-MM-dd'
        $settingsMigrated = 0

        # Map friendly category names to .inf section headers
        $categoryToSection = @{
            'SystemAccess'    = 'System Access'
            'AuditPolicy'     = 'Event Audit'
            'UserRights'      = 'Privilege Rights'
            'SecurityOptions' = 'Registry Values'
        }
    }

    process {
        # ------------------------------------------------------------------
        # Step 1: Read local security policy from the source server
        # ------------------------------------------------------------------
        Write-Verbose "Step 1: Reading local security policy from '$SourceComputer'..."
        $settings = Get-LocalSecurityPolicy -ComputerName $SourceComputer
        $settingsRead = ($settings | Measure-Object).Count

        if ($settingsRead -eq 0) {
            Write-Warning "No security policy settings found on '$SourceComputer'. Nothing to migrate."
            return [PSCustomObject]@{
                SourceComputer   = $SourceComputer
                GPOName          = $GPOName
                SettingsRead     = 0
                SettingsMigrated = 0
                Categories       = $Categories
                Timestamp        = $timestamp
            }
        }

        Write-Verbose "Found $settingsRead security policy setting(s)."

        # Filter by categories
        if ($Categories -notcontains 'All') {
            $settings = $settings | Where-Object { $Categories -contains $_.Category }
            Write-Verbose "Filtered to $($settings.Count) setting(s) in categories: $($Categories -join ', ')"
        }

        $filteredCategories = ($settings | Select-Object -ExpandProperty Category -Unique)

        if (-not $settings -or ($settings | Measure-Object).Count -eq 0) {
            Write-Warning "No settings match the specified categories."
            return
        }

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
                        $gpo = New-GPO -Name $GPOName -Comment "Security policy migrated from $SourceComputer on $timestamp. Created by LocalPolicy-ToGPO module." -ErrorAction Stop
                        Write-Verbose "Created GPO '$GPOName'."
                    }
                    catch {
                        Write-Error "Failed to create GPO '$GPOName': $_"
                        return
                    }
                }
                else {
                    Write-Verbose "GPO creation skipped (WhatIf mode)."
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
        # Step 3: Build the GptTmpl.inf content
        # ------------------------------------------------------------------
        Write-Verbose "Step 3: Generating GptTmpl.inf content..."

        $infBuilder = [System.Text.StringBuilder]::new()
        [void]$infBuilder.AppendLine('[Unicode]')
        [void]$infBuilder.AppendLine('Unicode=yes')
        [void]$infBuilder.AppendLine("[Version]")
        [void]$infBuilder.AppendLine('signature="$CHICAGO$"')
        [void]$infBuilder.AppendLine("Revision=1")
        [void]$infBuilder.AppendLine("; Migrated from $SourceComputer on $timestamp by LocalPolicy-ToGPO module")
        [void]$infBuilder.AppendLine()

        # Group settings by their .inf section
        foreach ($category in $filteredCategories) {
            $sectionName = $categoryToSection[$category]
            if (-not $sectionName) { continue }

            $sectionSettings = $settings | Where-Object { $_.Category -eq $category }

            [void]$infBuilder.AppendLine("[$sectionName]")

            foreach ($setting in $sectionSettings) {
                [void]$infBuilder.AppendLine("$($setting.SettingName) = $($setting.SettingValue)")
                $settingsMigrated++
            }

            [void]$infBuilder.AppendLine()
        }

        $infContent = $infBuilder.ToString()
        Write-Verbose "Generated GptTmpl.inf with $settingsMigrated setting(s)."

        # ------------------------------------------------------------------
        # Step 4: Write GptTmpl.inf to the GPO SYSVOL path
        # ------------------------------------------------------------------
        Write-Verbose "Step 4: Writing GptTmpl.inf to GPO SYSVOL path..."

        if ($gpo) {
            $gpoId   = $gpo.Id.ToString('B').ToUpper()
            $domainName = $null
            try {
                $domainName = (Get-ADDomain -ErrorAction Stop).DNSRoot
            }
            catch {
                try {
                    $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                }
                catch {
                    Write-Error "Unable to determine domain name."
                    return
                }
            }

            $gpoPath = "\\$domainName\SYSVOL\$domainName\Policies\$gpoId\Machine\Microsoft\Windows NT\SecEdit"

            if ($PSCmdlet.ShouldProcess("$gpoPath\GptTmpl.inf", 'Write security policy settings to GPO')) {
                try {
                    # Create the directory structure if needed
                    if (-not (Test-Path $gpoPath)) {
                        New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null
                        Write-Verbose "Created directory: $gpoPath"
                    }

                    # Write the .inf file
                    $infFilePath = Join-Path $gpoPath 'GptTmpl.inf'
                    Set-Content -Path $infFilePath -Value $infContent -Encoding Unicode -Force
                    Write-Verbose "Wrote GptTmpl.inf to '$infFilePath'."

                    # ------------------------------------------------------------------
                    # Step 5: Update GPO version to force replication
                    # ------------------------------------------------------------------
                    Write-Verbose "Step 5: Updating GPO version to trigger replication..."

                    $gptIniPath = "\\$domainName\SYSVOL\$domainName\Policies\$gpoId\GPT.INI"
                    if (Test-Path $gptIniPath) {
                        $gptContent = Get-Content -Path $gptIniPath -Raw
                        if ($gptContent -match 'Version=(\d+)') {
                            $currentVersion = [int]$Matches[1]
                            # Increment the machine portion (lower 16 bits)
                            $newVersion = $currentVersion + 1
                            $newGptContent = $gptContent -replace "Version=\d+", "Version=$newVersion"
                            Set-Content -Path $gptIniPath -Value $newGptContent -Encoding ASCII -Force
                            Write-Verbose "Updated GPT.INI version from $currentVersion to $newVersion."
                        }
                    }

                    # Also update the AD version attribute
                    try {
                        $gpo.MakeAclConsistent()
                    }
                    catch {
                        Write-Verbose "Could not update AD GPO version (non-critical): $_"
                    }
                }
                catch {
                    Write-Error "Failed to write GptTmpl.inf to GPO path: $_"
                    return
                }
            }
        }
        else {
            Write-Verbose "GPO object not available (WhatIf mode). Would write $settingsMigrated settings to GptTmpl.inf."
        }
    }

    end {
        $summary = [PSCustomObject]@{
            SourceComputer   = $SourceComputer
            GPOName          = $GPOName
            SettingsRead     = $settingsRead
            SettingsMigrated = $settingsMigrated
            Categories       = $filteredCategories -join ', '
            Timestamp        = $timestamp
        }

        Write-Verbose "Migration complete: $settingsRead read, $settingsMigrated migrated."
        $summary
    }
}
