<#
.SYNOPSIS
  Regression test for Microsoft 365 collections: builds the synthetic Purview
  audit log export, runs CsirtTriage headless and checks the layout and the
  expected detections (see tools\New-M365TestCase.ps1 for the scenario).

.EXAMPLE
  dotnet build; .\tools\Test-M365Detections.ps1 -Exe src\CsirtTriage.Cli\bin\Debug\net8.0\csirttriage.dll
#>
param(
    [Parameter(Mandatory)] [string] $Exe,
    [string] $WorkFolder = (Join-Path ([IO.Path]::GetTempPath()) 'M365Regression')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { throw "Build first: $Exe not found." }

$marker = Join-Path $WorkFolder '.m365-regression'
if (Test-Path $WorkFolder) {
    if (-not (Test-Path $marker)) { throw "$WorkFolder exists and was not created by this script; choose another -WorkFolder." }
    Remove-Item -LiteralPath $WorkFolder -Recurse -Force
}
& (Join-Path $PSScriptRoot 'New-M365TestCase.ps1') -CaseFolder $WorkFolder | Out-Null
Set-Content -Path $marker -Value 'created by Test-M365Detections.ps1'
Copy-Item (Join-Path $PSScriptRoot 'example-iocs.txt') (Join-Path $WorkFolder 'iocs.txt')

$runArgs = @('--case', $WorkFolder, '--name', 'Regression', '--m365-only')
if ($Exe -like '*.dll') { $file = 'dotnet'; $runArgs = @($Exe) + $runArgs } else { $file = $Exe }
$log = Join-Path $WorkFolder 'run.log'
$p = Start-Process -FilePath $file -ArgumentList $runArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $log
if ($p.ExitCode -ne 0) { throw "CsirtTriage exited with $($p.ExitCode); see $log" }
$runLog = Get-Content $log -Raw -Encoding UTF8

$out = Join-Path $WorkFolder 'Level2\M365'
$failed = 0
function Check([bool] $ok, [string] $what) {
    if ($ok) { Write-Host "  PASS  $what" } else { Write-Host "  FAIL  $what" -ForegroundColor Red; $script:failed++ }
}
$findings = @(Import-Csv (Join-Path $out 'Findings.csv') -Encoding UTF8)
function Has([string] $severity, [string] $source, [string] $pattern) {
    Check (@($findings | Where-Object { $_.Severity -eq $severity -and $_.Source -eq $source -and $_.Text -match $pattern }).Count -gt 0) "$severity [$source] $pattern"
}

Write-Host 'Scan and layout'
Check ($runLog -match 'Audit_Search_INC-4711_20261104\.csv: 243 record') 'current Purview layout read (243 records)'
Check ($runLog -match 'AuditLog_classic_20261104\.csv: 21 record') 'classic layout read (21 records)'
Check ($runLog -match 'Tenant: corp\.example') 'tenant named after its mail domain'
Check ($runLog -match 'InteractiveSignIns_2026-11-01_2026-11-04\.csv: 30 Entra sign-in') 'Entra interactive sign-ins read (30)'
Check ($runLog -match 'NonInteractiveSignIns_2026-11-01_2026-11-04\.csv: 10 Entra sign-in') 'Entra non-interactive sign-ins read (10)'
Check ($runLog -match 'AuthDetails.*not used') 'Entra AuthDetails file recognised and skipped'
Check (Test-Path (Join-Path $WorkFolder 'Processed\M365\Normalized_ENTRA.csv')) 'Normalized_ENTRA.csv in Processed\M365'
Check (Test-Path (Join-Path $WorkFolder 'Processed\M365\Normalized_UAL.csv')) 'Normalized_UAL.csv in Processed\M365'
foreach ($f in '.processed', 'QuickWins.rtf', 'Findings.csv', 'Logons.csv', 'IocHits.csv', 'host.txt') { Check (Test-Path (Join-Path $out $f)) "Level2\M365\$f" }
Check ((Get-Content (Join-Path $out 'host.txt') -Raw) -match 'Kind=M365') 'host.txt records the collection type'

Write-Host 'Sign-ins'
Has 'CRITICAL' 'M365-SIGNIN' 'Brute force succeeded: jdoe@corp\.example signed in from 203\.0\.113\.45 after 12 failed'
Has 'HIGH' 'M365-SIGNIN' 'Password spray: 6 account\(s\) tried from 198\.51\.100\.77'
Has 'HIGH' 'M365-SIGNIN' 'Legacy authentication \(ROPC, no MFA\) sign-in: cfo@corp\.example'
Has 'MEDIUM' 'M365-SIGNIN' 'sales@corp\.example signed in from 6 different IP addresses'

Write-Host 'Mailbox'
Has 'CRITICAL' 'M365-MAILBOX' "Inbox rule '\.\.' created for jdoe@corp\.example: moves to RSS Feeds, marks as read, when invoice"
Has 'HIGH' 'M365-MAILBOX' "Inbox rule 'Sync' created for cfo@corp\.example: forwards to collect@evil-update\.example"
Has 'CRITICAL' 'M365-MAILBOX' 'Mailbox forwarding set on jdoe@corp\.example to collect@evil-update\.example \(external domain\)'
Has 'SUSPICIOUS' 'M365-MAILBOX' "Inbox rule 'Newsletters'"
Has 'MEDIUM' 'M365-MAILBOX' 'Mailbox permission FullAccess on cfo@corp\.example granted to jdoe'
Has 'CRITICAL' 'M365-MAILBOX' 'Unified audit logging switched off'
Has 'HIGH' 'M365-MAILBOX' "Content search export on 'all-mail'"

Write-Host 'Directory'
Has 'CRITICAL' 'M365-DIRECTORY' "jdoe@corp\.example added to role 'Global Administrator'"
Has 'HIGH' 'M365-DIRECTORY' "Consent to application 'Mail Sync Pro'"
Has 'HIGH' 'M365-DIRECTORY' "Credentials added to application 'Mail Sync Pro'"
Has 'MEDIUM' 'M365-DIRECTORY' 'User registered security info: jdoe@corp\.example'
Has 'MEDIUM' 'M365-DIRECTORY' 'Password reset for reception@corp\.example'
Has 'CRITICAL' 'M365-DIRECTORY' 'Set federation settings on domain: corp\.example'

Write-Host 'Files and mail access'
Has 'HIGH' 'M365-FILES' 'Mass download: jdoe@corp\.example downloaded 120 file'
Has 'MEDIUM' 'M365-FILES' "3 'Anyone' sharing links created by jdoe"
Has 'HIGH' 'M365-MAILACCESS' '650 mail item\(s\) of cfo@corp\.example'
Check (@($findings | Where-Object Source -ne 'ENTRA-SIGNIN').Count -eq 20) "20 audit log findings, no extra noise (got $(@($findings | Where-Object Source -ne 'ENTRA-SIGNIN').Count))"

Write-Host 'Entra sign-ins'
Has 'CRITICAL' 'ENTRA-SIGNIN' 'Sign-in from a new country for jdoe@corp\.example: Amsterdam.*NL from 203\.0\.113\.45 \(usually SE\) — hosting provider AS14061'
Has 'HIGH' 'ENTRA-SIGNIN' 'Impossible travel for jdoe@corp\.example: Stockholm.*at 08:50 and Amsterdam.*at 09:05 UTC, 15 min apart'
Has 'HIGH' 'ENTRA-SIGNIN' 'Session of jdoe@corp\.example used from SE and NL — possible stolen session token'
Has 'CRITICAL' 'ENTRA-SIGNIN' 'Brute force succeeded: jdoe@corp\.example signed in from 203\.0\.113\.45 after 12 failed'
Has 'HIGH' 'ENTRA-SIGNIN' 'Correct password for jdoe@corp\.example from 198\.51\.100\.201.*stopped by the MFA requirement'
Has 'MEDIUM' 'ENTRA-SIGNIN' 'jdoe@corp\.example from 203\.0\.113\.50 \(Lagos.*blocked by Conditional Access'
Has 'CRITICAL' 'ENTRA-SIGNIN' 'MFA fatigue succeeded: 4 MFA prompt\(s\) for cfo@corp\.example'
Has 'CRITICAL' 'ENTRA-SIGNIN' 'Sign-in from a new country for cfo@corp\.example: Ashburn.*US'
Has 'CRITICAL' 'ENTRA-SIGNIN' 'Sign-in from a new country for cfo@corp\.example: Amsterdam.*single-factor'
Has 'HIGH' 'ENTRA-SIGNIN' 'Impossible travel for cfo@corp\.example: Ashburn'
Has 'HIGH' 'ENTRA-SIGNIN' 'cfo@corp\.example with legacy client IMAP4'
Has 'HIGH' 'ENTRA-SIGNIN' 'cfo@corp\.example with a scripted client \(python-requests\)'
Check (@($findings | Where-Object Source -eq 'ENTRA-SIGNIN').Count -eq 12) "12 Entra sign-in findings, no extra noise (got $(@($findings | Where-Object Source -eq 'ENTRA-SIGNIN').Count))"
Check (@(Import-Csv (Join-Path $out 'Logons.csv') | Where-Object { $_.Via -like 'Sign-in log*' -and $_.SourceIp -eq '198.51.100.200' }).Count -eq 1) 'Entra sign-ins in Logons.csv'

Write-Host 'Shared outputs'
$logons = @(Import-Csv (Join-Path $out 'Logons.csv'))
# One row per source of the sign-in: audit log, Entra export (interactive and non-interactive)
Check (@($logons | Where-Object { $_.User -eq 'jdoe@corp.example' -and $_.SourceIp -eq '203.0.113.45' -and $_.LogonType -eq 'M365' }).Count -ge 1) 'attacker sign-in in Logons.csv'
$hits = @(Import-Csv (Join-Path $out 'IocHits.csv'))
Check (@($hits | Where-Object Ioc -eq '203.0.113.45').Count -eq 1) 'case IOC 203.0.113.45 hit'
Check (@($hits | Where-Object Ioc -eq 'evil-update.example').Count -eq 1) 'case IOC domain evil-update.example hit (forwarding address)'
Check (@($hits | Where-Object Ioc -eq '198.51.100.0/24').Count -eq 1) 'case IOC CIDR hit'

if ($failed -gt 0) { Write-Host "$failed check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host 'All checks passed.'
