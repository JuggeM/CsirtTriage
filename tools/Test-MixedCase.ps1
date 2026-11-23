<#
.SYNOPSIS
  Regression test for a case with both UAC and KAPE collections, analysed in
  parallel: one case summary across Linux and Windows hosts, an ORC
  collection still waiting for KAPE, and re-analysis keeping earlier results.

.EXAMPLE
  dotnet build; .\tools\Test-MixedCase.ps1 -Exe src\CsirtTriage.Cli\bin\Debug\net8.0\csirttriage.dll
#>
param(
    [Parameter(Mandatory)] [string] $Exe,
    [string] $WorkFolder = (Join-Path ([IO.Path]::GetTempPath()) 'MixedRegression')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { throw "Build first: $Exe not found." }

$marker = Join-Path $WorkFolder '.mixed-regression'
if (Test-Path $WorkFolder) {
    if (-not (Test-Path $marker)) { throw "$WorkFolder exists and was not created by this script; choose another -WorkFolder." }
    Remove-Item -LiteralPath $WorkFolder -Recurse -Force
}
& (Join-Path $PSScriptRoot 'New-UacTestCase.ps1') -Path $WorkFolder | Out-Null
& (Join-Path $PSScriptRoot 'New-KapeTestCase.ps1') -CaseFolder $WorkFolder 3>$null | Out-Null
Set-Content -Path $marker -Value 'created by Test-MixedCase.ps1'
Copy-Item (Join-Path $PSScriptRoot 'example-iocs.txt') (Join-Path $WorkFolder 'iocs.txt') -Force
# An ORC collection the processing script hasn't handled yet
New-Item -ItemType Directory -Force (Join-Path $WorkFolder 'Decompressed/ORC_WorkStation_WS99_20261103_080000/Windows') | Out-Null

function Run([string[]] $extra, [string] $logName) {
    $runArgs = @('--case', $WorkFolder, '--name', 'Mixed') + $extra
    if ($Exe -like '*.dll') { $file = 'dotnet'; $runArgs = @($Exe) + $runArgs } else { $file = $Exe }
    $log = Join-Path $WorkFolder $logName
    $p = Start-Process -FilePath $file -ArgumentList $runArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $log
    return @{ Code = $p.ExitCode; Log = (Get-Content $log -Raw -Encoding UTF8) }
}

$failed = 0
function Check([bool] $ok, [string] $what) {
    if ($ok) { Write-Host "  PASS  $what" } else { Write-Host "  FAIL  $what" -ForegroundColor Red; $script:failed++ }
}

Write-Host 'Scan'
$list = (Run @('--list') 'list.log').Log
Check ($list -match 'ORC_WorkStation_WS99_20261103_080000\s+WS99\s+KAPE.*Waiting for KAPE') 'ORC collection without KAPE output: waiting'
Check ($list -match 'WS01\s+WS01\s+KAPE.*KAPE output ready') 'KAPE host ready'
Check ($list -match 'uac-web01-linux-20261101\s+web01\s+UAC.*Not extracted') 'UAC archive not extracted'
Check ($list -match 'uac-mail01-linux-20261104\s+mail01\s+UAC.*Analysed') 'UAC collection already analysed'

Write-Host 'Parallel run'
$run = Run @('--parallel', '4') 'run.log'
Check ($run.Code -eq 3) "exit code 3, one failed collection (got $($run.Code))"
Check ($run.Log -match 'Running 8 collection\(s\), up to 4 at a time') 'eight collections selected (mail01 already analysed)'
Check ($run.Log -match 'Run finished: 7 analysed, 1 failed, 0 cancelled') 'seven analysed, the corrupt archive failed'
$level2 = Join-Path $WorkFolder 'Level2'
$infos = Get-ChildItem $level2 -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'host.txt') } |
    ForEach-Object { Get-Content (Join-Path $_.FullName 'host.txt') -Raw }
Check (@($infos | Where-Object { $_ -match 'Kind=UAC' }).Count -eq 4) 'four UAC collections in Level2\'
Check (@($infos | Where-Object { $_ -match 'Kind=KAPE' }).Count -eq 3) 'three KAPE collections in Level2\'

Write-Host 'One case across Linux and Windows'
$summary = Get-Content (Join-Path $level2 'CaseSummary.txt') -Raw -Encoding UTF8
Check ($summary -match 'Hosts: 7') 'case summary covers all seven hosts'
foreach ($h in 'web01', 'db01', 'WS01', 'DC01', 'FS01') { Check ($summary -match "(?m)^\s+$h\s+\d+") "$h ranked in the case summary" }
$caseFindings = @(Import-Csv (Join-Path $level2 'CaseFindings.csv') -Encoding UTF8)
Check (@($caseFindings | Where-Object Source -eq 'EVTX').Count -gt 0 -and @($caseFindings | Where-Object Source -eq 'AUTH').Count -gt 0) 'CaseFindings.csv has Windows and Linux findings'

Write-Host 'Re-analyse keeps earlier results'
$re = Run @('--only', 'WS01,uac-web01-linux-20261101') 'rerun.log'
Check ($re.Code -eq 0) "re-run exit code 0 (got $($re.Code))"
$previous = Join-Path $level2 '_previous'
Check (@(Get-ChildItem $previous -Directory -Filter 'WS01-*').Count -eq 1) 'earlier WS01 results moved to Level2\_previous'
Check (@(Get-ChildItem $previous -Directory -Filter 'uac-web01-linux-20261101-*').Count -eq 1) 'earlier web01 results moved to Level2\_previous'
Check (Test-Path (Join-Path $level2 'WS01/.processed')) 'WS01 analysed again'
$summary2 = Get-Content (Join-Path $level2 'CaseSummary.txt') -Raw -Encoding UTF8
Check ($summary2 -match 'Hosts: 7') '_previous is not counted as a host'

if ($failed -gt 0) { Write-Host "$failed check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host 'All checks passed.'
