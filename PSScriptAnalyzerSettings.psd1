@{
    Severity = @('Error', 'Warning')

    # Write-Host is intentional for this interactive console application.
    # The background-job variables are declared in the job script block and
    # supplied through Start-Job -ArgumentList. No caller scope is captured.
    # Host values in tests use only synthetic example and documentation ranges.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
        'PSAvoidUsingComputerNameHardcoded'
        'PSUseUsingScopeModifierInNewRunspaces'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
