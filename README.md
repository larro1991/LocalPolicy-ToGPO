# LocalPolicy-ToGPO

Migrate local policy settings to domain Group Policy Objects. Reads local firewall rules and security policy from servers and creates equivalent GPO settings for centralized management.

---

> **WARNING: This module NEVER modifies local policy.**
>
> It reads from local servers and writes to GPOs. After verifying the GPO is correct, **YOU** decide when to link it and clean up local settings. The source server is treated as read-only at all times.

---

## The Problem

You inherited 30 servers with firewall rules configured locally. Each one has 15-40 rules created by hand over the years. Compliance says everything needs to be in Group Policy. The manual process takes hours per server: open the firewall snap-in, write down every rule, open GPMC, recreate each rule in the GPO, pray you did not miss one.

Common scenarios:
- Inherited infrastructure where the previous admin configured everything locally
- Compliance audit requires all firewall rules delivered via GPO
- Server migration project where local rules need to be captured before decommissioning
- Standardization effort across a fleet of servers with inconsistent local configurations

This module automates the read-and-migrate workflow so you can centralize local policy into GPOs safely and repeatably.

## Workflow

The module follows a deliberate export-review-migrate-verify workflow to prevent accidents:

```
1. EXPORT    -->  Get-LocalFirewallPolicy / Get-LocalSecurityPolicy
                  Read local settings and optionally save to JSON for review

2. REVIEW    -->  Open the JSON export and verify the rules make sense
                  Remove anything you do not want in the GPO

3. MIGRATE   -->  Copy-FirewallToGPO / Copy-SecurityPolicyToGPO
                  Create the rules in a GPO (use -WhatIf first!)

4. COMPARE   -->  Compare-PolicyCompliance
                  Verify the GPO matches the local settings

5. LINK      -->  You link the GPO to the appropriate OU yourself

6. CLEANUP   -->  You remove local rules when satisfied the GPO is working
```

## Quick Start

### Step 1: Export local firewall rules for review

```powershell
Import-Module .\LocalPolicy-ToGPO.psd1

# Export rules from a server to JSON for review
Get-LocalFirewallPolicy -ComputerName "SVR-WEB-01" -ExportPath .\svr-web-01-firewall.json

# Review the export
Get-Content .\svr-web-01-firewall.json | ConvertFrom-Json | Format-Table DisplayName, Direction, Action, Protocol, LocalPort
```

### Step 2: Preview the migration with -WhatIf

```powershell
Copy-FirewallToGPO -SourceComputer "SVR-WEB-01" -GPOName "Firewall-WebServers" -CreateGPO -WhatIf
```

### Step 3: Run the migration

```powershell
Copy-FirewallToGPO -SourceComputer "SVR-WEB-01" -GPOName "Firewall-WebServers" -CreateGPO
```

### Step 4: Verify the migration

```powershell
Compare-PolicyCompliance -ComputerName "SVR-WEB-01" -GPOName "Firewall-WebServers" -OutputPath .\compliance-report.html
```

### Step 5: Link the GPO (you do this yourself)

```powershell
# This is YOUR decision -- the module does not link GPOs
New-GPLink -Name "Firewall-WebServers" -Target "OU=WebServers,DC=contoso,DC=com"
```

## Example Output

### Migration Summary

```
SourceComputer : SVR-WEB-01
GPOName        : Firewall-WebServers
RulesRead      : 23
RulesMigrated  : 23
RulesFailed    : 0
Timestamp      : 2026-02-16
```

### Compliance Comparison

```
SettingName              LocalValue                    GPOValue                      Match Finding
-----------              ----------                    --------                      ----- -------
Allow HTTP Inbound       Inbound=Inbound Action=Allow  Inbound=Inbound Action=Allow  True  MATCH
Allow HTTPS Inbound      Inbound=Inbound Action=Allow  Inbound=Inbound Action=Allow  True  MATCH
Allow RDP from Mgmt      Inbound=Inbound Action=Allow  Inbound=Inbound Action=Allow  True  MATCH
Custom App Port 8443     Inbound=Inbound Action=Allow  N/A                           False MISSING FROM GPO
```

## Functions

| Function | Purpose |
|---|---|
| `Get-LocalFirewallPolicy` | Read local firewall rules from a server (never modifies) |
| `Get-LocalSecurityPolicy` | Read local security policy settings from a server (never modifies) |
| `Copy-FirewallToGPO` | Copy firewall rules into a GPO (writes to GPO only) |
| `Copy-SecurityPolicyToGPO` | Copy security policy settings into a GPO (writes to GPO only) |
| `Compare-PolicyCompliance` | Compare local policy against a GPO to verify migration |

## Security Policy Migration

```powershell
# Export security policy for review
Get-LocalSecurityPolicy -ComputerName "SVR-WEB-01" -ExportPath .\secpol-export.json

# Migrate specific categories
Copy-SecurityPolicyToGPO -SourceComputer "SVR-WEB-01" -GPOName "Security-WebServers" -Categories AuditPolicy,UserRights -CreateGPO

# Migrate everything
Copy-SecurityPolicyToGPO -SourceComputer "SVR-WEB-01" -GPOName "Security-WebServers" -CreateGPO
```

## Batch Migration

```powershell
# Migrate multiple servers
$servers = "SVR-WEB-01", "SVR-WEB-02", "SVR-WEB-03"

foreach ($server in $servers) {
    # Each server gets its own GPO for review
    $gpoName = "Firewall - $server - Migrated $(Get-Date -Format 'yyyy-MM-dd')"
    Copy-FirewallToGPO -SourceComputer $server -GPOName $gpoName -CreateGPO
}

# Or migrate all into one shared GPO (if rules should be identical)
$servers | ForEach-Object {
    Copy-FirewallToGPO -SourceComputer $_ -GPOName "Firewall-WebServers-Shared" -CreateGPO
}
```

## Requirements

- **PowerShell 5.1** or later
- **GroupPolicy** RSAT module (for GPO creation and management)
- **NetSecurity** module (built into Windows, for firewall rule management)
- **Domain admin** or delegated GPO creation rights
- **WinRM** enabled on target servers (for remote reads)

## What About the Local Rules After Migration?

The module intentionally does NOT remove local rules. After migration, follow this process:

1. **Verify the GPO is correct** using `Compare-PolicyCompliance`
2. **Link the GPO** to the server's OU
3. **Run `gpupdate /force`** on the server
4. **Verify rules now come from GPO** by checking `Get-NetFirewallRule | Where-Object PolicyStoreSourceType -eq 'GroupPolicy'`
5. **Then manually remove local rules** when you are satisfied the GPO is delivering them correctly

This is a deliberate design choice. Automatically deleting local rules during migration is dangerous -- if the GPO is not linked or has a scope problem, you would lose firewall protection. Keep the local rules as a safety net until you have confirmed the GPO works.

## Design Decisions

| Decision | Rationale |
|---|---|
| Read-only on source | Never risk breaking a production server's firewall during migration |
| Audit trail in descriptions | Every migrated rule's description shows where it came from and when |
| WhatIf on all writes | Preview every change before committing |
| Export-review-migrate workflow | Forces the admin to look at the data before acting on it |
| Per-server or batched | Supports both one-GPO-per-server and shared-GPO patterns |
| No automatic GPO linking | Linking is a policy decision the admin must make deliberately |
| No local rule cleanup | Removing local rules is irreversible and should be a conscious choice |

## Feedback & Contributions

This tool was built to solve real admin pain points. If you have ideas for improvement, find a bug, or want to suggest a feature:

- **Open an issue** on this repo — [Issues](../../issues)
- Feature requests, bug reports, and general feedback are all welcome
- Pull requests are appreciated if you want to contribute directly

If you find this useful, check out my other tools at [larro1991.github.io](https://larro1991.github.io)

## License

MIT License. See [LICENSE](LICENSE) for details.
