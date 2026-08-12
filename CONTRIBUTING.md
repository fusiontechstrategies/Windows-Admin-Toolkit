# Contributing

Thank you for helping improve Windows Admin Toolkit.

## Before opening an issue

- Search existing issues for the same behavior or proposal.
- Remove credentials, real hostnames, private inventory, tokens, and confidential logs.
- Include the PowerShell edition, exact version, Windows version, and reproducible steps for bugs.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md) and must not be reported publicly.

## Pull requests

1. Fork the repository and create a focused branch.
2. Keep the application implementation in `WindowsAdminToolkit.ps1`.
3. Preserve Windows PowerShell 5.1 and PowerShell 7.x compatibility.
4. Add or update dependency-free tests for behavior changes.
5. Update documentation when behavior, parameters, or security boundaries change.
6. Run the test and analysis commands below.
7. Open a pull request with a clear summary, risk assessment, and validation record.

## Required validation

```powershell
powershell.exe -NoLogo -NoProfile -File .\tests\Run-Tests.ps1
pwsh.exe -NoLogo -NoProfile -File .\tests\Run-Tests.ps1

Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

Both test runs must pass. Static analysis must report zero findings.

## Project standards

- Prefer clear, conservative administration behavior over clever shortcuts.
- Never use `Invoke-Expression`.
- Never place plaintext credentials in process arguments, logs, reports, or source.
- Do not bypass execution policy or silently alter remote-management security settings.
- Use literal paths for filesystem operations and validate all external input.
- State-changing actions require `ShouldProcess` and an exact confirmation phrase.
- Automatic retries are limited to read-only actions.
- Use ASCII-compatible text in the application script for Windows PowerShell 5.1 console reliability.
- Do not use em dashes in source, documentation, tests, issues, or pull requests.
- Keep commits small, descriptive, and free of generated reports or private target lists.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
