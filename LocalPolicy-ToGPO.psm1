# LocalPolicy-ToGPO Module Loader
# Dot-source all public and private functions

$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1"  -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)

foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
        Write-Verbose "Imported $($import.FullName)"
    }
    catch {
        Write-Error "Failed to import $($import.FullName): $_"
    }
}

# Export only public functions
Export-ModuleMember -Function $Public.BaseName
