function New-HtmlDashboard {
    <#
    .SYNOPSIS
        Generates an HTML dashboard with dark theme and cyan/teal accent.
    .DESCRIPTION
        Internal helper function that generates styled HTML reports for policy
        compliance comparisons. Uses a dark theme with #56d4dd cyan/teal accent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$GeneratedDate,

        [Parameter()]
        [array]$SummaryCards = @(),

        [Parameter()]
        [array]$Sections = @(),

        [Parameter()]
        [array]$Findings = @()
    )

    $cardHtml = foreach ($card in $SummaryCards) {
        @"
            <div class="card" style="border-top: 3px solid $($card.Color);">
                <div class="card-value" style="color: $($card.Color);">$($card.Value)</div>
                <div class="card-label">$($card.Label)</div>
            </div>
"@
    }

    # Build findings table rows
    $tableRows = foreach ($finding in $Findings) {
        $rowClass = switch -Wildcard ($finding.Finding) {
            'MATCH'            { 'row-match' }
            'MISMATCH*'        { 'row-mismatch' }
            'MISSING FROM GPO' { 'row-missing' }
            'EXTRA IN GPO'     { 'row-extra' }
            default            { '' }
        }

        $findingBadge = switch -Wildcard ($finding.Finding) {
            'MATCH'            { '<span class="badge badge-match">MATCH</span>' }
            'MISMATCH*'        { '<span class="badge badge-mismatch">MISMATCH</span>' }
            'MISSING FROM GPO' { '<span class="badge badge-missing">MISSING FROM GPO</span>' }
            'EXTRA IN GPO'     { '<span class="badge badge-extra">EXTRA IN GPO</span>' }
            default            { $finding.Finding }
        }

        $detailText = if ($finding.Finding -like 'MISMATCH*') {
            $finding.Finding -replace '^MISMATCH:\s*', ''
        } else {
            ''
        }

        @"
                    <tr class="$rowClass">
                        <td>$($finding.SettingName)</td>
                        <td>$($finding.CompareType)</td>
                        <td>$($finding.LocalValue)</td>
                        <td>$($finding.GPOValue)</td>
                        <td>$findingBadge</td>
                        <td class="detail-text">$detailText</td>
                    </tr>
"@
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #56d4dd;
        }
        header h1 {
            color: #56d4dd;
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
        }
        header .subtitle {
            color: #888;
            font-size: 0.9rem;
        }
        .cards {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-bottom: 2rem;
            justify-content: center;
        }
        .card {
            background: #16213e;
            border-radius: 8px;
            padding: 1.5rem 2rem;
            min-width: 180px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        .card-value {
            font-size: 2.5rem;
            font-weight: 700;
        }
        .card-label {
            font-size: 0.85rem;
            color: #aaa;
            margin-top: 0.3rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .section {
            background: #16213e;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        .section h2 {
            color: #56d4dd;
            font-size: 1.2rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #2a2a4a;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        th {
            background: #0f3460;
            color: #56d4dd;
            padding: 0.75rem 1rem;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            position: sticky;
            top: 0;
        }
        td {
            padding: 0.6rem 1rem;
            border-bottom: 1px solid #2a2a4a;
            vertical-align: top;
        }
        tr:hover { background: rgba(86, 212, 221, 0.05); }
        .row-match td:first-child { border-left: 3px solid #4caf50; }
        .row-mismatch td:first-child { border-left: 3px solid #f44336; }
        .row-missing td:first-child { border-left: 3px solid #ff9800; }
        .row-extra td:first-child { border-left: 3px solid #9c27b0; }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-match { background: rgba(76,175,80,0.2); color: #4caf50; }
        .badge-mismatch { background: rgba(244,67,54,0.2); color: #f44336; }
        .badge-missing { background: rgba(255,152,0,0.2); color: #ff9800; }
        .badge-extra { background: rgba(156,39,176,0.2); color: #9c27b0; }
        .detail-text { color: #f44336; font-style: italic; font-size: 0.8rem; }
        footer {
            text-align: center;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #2a2a4a;
            color: #555;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>$Title</h1>
            <div class="subtitle">Generated $GeneratedDate by LocalPolicy-ToGPO</div>
        </header>

        <div class="cards">
$($cardHtml -join "`n")
        </div>

        <div class="section">
            <h2>Compliance Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Setting Name</th>
                        <th>Type</th>
                        <th>Local Value</th>
                        <th>GPO Value</th>
                        <th>Finding</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
$($tableRows -join "`n")
                </tbody>
            </table>
        </div>

        <footer>
            LocalPolicy-ToGPO Module &mdash; Read-only on source, write to GPO only.
        </footer>
    </div>
</body>
</html>
"@
}
