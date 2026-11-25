<#
.SYNOPSIS
    Builds the complete CsirtTriage test case: Linux (UAC), Windows (DFIR ORC → KAPE)
    and Microsoft 365 (unified audit log + Entra sign-in logs) in one case folder,
    with a checklist (TESTING.md) of what to look for in every part of the app.
    Optionally zips it.

.DESCRIPTION
    One incident (INC-4711) across all three platforms, from the same attacker
    IP (203.0.113.45), plus collections in every state the collections table
    can show: not extracted, extracted, KAPE output ready, waiting for KAPE,
    already analysed, a corrupt archive and an interrupted earlier run.
    All IPs and domains are from documentation ranges (RFC 5737 / RFC 2606).

    With -Exe (the csirttriage CLI or CsirtTriage.exe), mail01 is analysed
    beforehand so it shows as "Analysed", and the expected results in
    TESTING.md are taken from a headless run of a copy of the case.

.EXAMPLE
    .\tools\New-FullTestCase.ps1 -Path C:\Cases\TestCase -Exe .\CsirtTriage.exe -Zip C:\Temp\CsirtTriage-TestCase.zip
#>
param(
    [Parameter(Mandatory)] [string] $Path,
    [string] $Exe,
    [string] $Zip
)
$ErrorActionPreference = 'Stop'
$case = Join-Path $Path 'INC-4711'
if (Test-Path $Path) {
    if (Get-ChildItem $Path -Force | Where-Object Name -ne 'INC-4711') { throw "$Path exists and holds other files; choose an empty or new folder." }
    if (Test-Path $case) { Remove-Item -LiteralPath $case -Recurse -Force }
}

# ── The three platforms ───────────────────────────────────────────────
& (Join-Path $PSScriptRoot 'New-UacTestCase.ps1') -Path $case | Out-Null
& (Join-Path $PSScriptRoot 'New-KapeTestCase.ps1') -CaseFolder $case 3>$null | Out-Null
& (Join-Path $PSScriptRoot 'New-M365TestCase.ps1') -CaseFolder $case | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'example-iocs.txt') (Join-Path $case 'iocs.txt') -Force
# An ORC collection the processing script hasn't handled yet
New-Item -ItemType Directory -Force (Join-Path $case 'Decompressed/ORC_WorkStation_WS02_20261103_080000/Windows/System32/winevt/Logs') | Out-Null
# mail01's "already analysed" output in the UAC regression case is a placeholder; replaced below or removed
Remove-Item -LiteralPath (Join-Path $case 'Level2/uac-mail01-linux-20261104') -Recurse -Force

function Run([string[]] $runArgs) {
    if ($Exe -like '*.dll') { $file = 'dotnet'; $runArgs = @($Exe) + $runArgs } else { $file = $Exe }
    $log = [IO.Path]::GetTempFileName()
    $p = Start-Process -FilePath $file -ArgumentList $runArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $log
    $text = Get-Content $log -Raw -Encoding UTF8
    Remove-Item $log
    return @{ Code = $p.ExitCode; Log = $text }
}

$expected = ''
if ($Exe) {
    $Exe = (Resolve-Path $Exe).Path
    # mail01 analysed beforehand, so the table shows a real "Analysed" collection
    $r = Run @('--case', $case, '--name', 'INC-4711 test case', '--only', 'uac-mail01-linux-20261104', '--no-ioc-search')
    if ($r.Code -ne 0) { throw "Pre-analysing mail01 failed ($($r.Code)):`n$($r.Log)" }
    # Level2\ then only holds mail01 (and file01's interrupted run): drop the case-wide files of that partial run
    Get-ChildItem (Join-Path $case 'Level2') -File | Remove-Item -Force

    # Expected results: a headless run of a copy, exactly as the app would do it with the defaults
    $copy = Join-Path ([IO.Path]::GetTempPath()) ('csirttriage-expected-' + [guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $case -Destination $copy -Recurse
    try {
        $list = (Run @('--case', $copy, '--list')).Log
        $r = Run @('--case', $copy, '--name', 'INC-4711 test case', '--parallel', '4')
        $level2 = Join-Path $copy 'Level2'
        $rows = foreach ($dir in Get-ChildItem $level2 -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'host.txt') } | Sort-Object Name) {
            $info = Get-Content (Join-Path $dir.FullName 'host.txt') | ConvertFrom-StringData
            $f = @(Import-Csv (Join-Path $dir.FullName 'Findings.csv') -Encoding UTF8)
            $hits = if (Test-Path (Join-Path $dir.FullName 'IocHits.csv')) { @(Import-Csv (Join-Path $dir.FullName 'IocHits.csv')).Count } else { 0 }
            "| $($dir.Name) | $($info.Kind) | $($info.Hostname) | $($f.Count) | $(@($f | Where-Object Severity -eq 'CRITICAL').Count) | $(@($f | Where-Object Severity -eq 'HIGH').Count) | $hits |"
        }
        $summary = Get-Content (Join-Path $level2 'CaseSummary.txt') -Raw -Encoding UTF8
        # Only the LATERAL MOVEMENT section (the case timeline below it also has arrows)
        $section = [regex]::Match($summary, '(?s)########## LATERAL MOVEMENT[^\n]*\n(.*?)\n\s*\n').Groups[1].Value
        $lateral = ($section -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { '    ' + $_.Trim() }) -join "`n"
        $multi = ($summary -split "`n" | Where-Object { $_ -match '203\.0\.113\.45\s+EXTERNAL' } | ForEach-Object { '    ' + $_.Trim() }) -join "`n"
        $finish = ([regex]::Match($r.Log, 'Run finished: .*')).Value
        $iocLine = ([regex]::Match($r.Log, 'IOC search: \d+ of \d+ case IOC\(s\) seen.*')).Value
        $expected = @"

## Expected results (from a run of this exact case with the default settings)

Run log: ``$finish`` and ``$iocLine``

| Collection | Type | Host | Findings | Critical | High | Case IOC hits |
|---|---|---|---|---|---|---|
$($rows -join "`n")

Lateral movement in the case summary:

$lateral

Sources logging on to several hosts:

$multi

``--list`` before the run:

``````
$($list.TrimEnd())
``````
"@
    }
    finally { Remove-Item -LiteralPath $copy -Recurse -Force -ErrorAction SilentlyContinue }
}

# ── The checklist ─────────────────────────────────────────────────────
$testing = @"
# CsirtTriage test case: INC-4711

One synthetic incident across Linux, Windows and Microsoft 365, built to exercise every part of CsirtTriage. Unpack the zip anywhere (a short path such as ``C:\Cases\`` is best: some file paths in the UAC collections are long), open **CsirtTriage.exe**, and choose ``INC-4711`` as the case folder.

All IPs and domains are from documentation ranges; nothing points at real systems. The attacker uses **203.0.113.45** everywhere.

## What is in the case

| Collection | Platform | State when you open the case | Tests |
|---|---|---|---|
| uac-web01-linux-20261101 | Linux (UAC) | Not extracted (archive in Uploads\) | Extraction, web attacks, webshell, cron persistence, journal, bash history, body file, SHA1 hashes |
| uac-db01-linux-20261102 | Linux (UAC) | Extracted | AI coding agents (Claude Code, Codex, Gemini CLI) |
| uac-app01-linux-20261103 | Linux (UAC) | Not extracted, empty folder + stale _partial_ folder | Recovering from an interrupted extraction |
| uac-mail01-linux-20261104 | Linux (UAC) | Analysed | Re-analysing (earlier results move to Level2\_previous) |
| uac-file01-linux-20261105 | Linux (UAC) | Extracted, with output from an interrupted run | Stale output replaced; live response: rootkit (ld.so.preload), UID 0 account, deleted binary |
| uac-broken-linux-20261106 | Linux (UAC) | Not extracted, **corrupt archive** | Error handling: fails, the others continue |
| WS01 | Windows (KAPE) | KAPE output ready | Brute force, RDP, mimikatz, rclone exfiltration (SRUM), browser downloads, PowerShell history, USB, … |
| DC01 | Windows (KAPE) | KAPE output ready | DCSync, Kerberoasting, password spray, admin group changes |
| ORC_Server_FS01_… | Windows (KAPE) | KAPE output ready | IIS/Tomcat webshells, web brute force, pass-the-hash |
| ORC_WorkStation_WS02_… | Windows (ORC) | **Waiting for KAPE** | An ORC collection your processing script hasn't handled: can't be ticked |
| M365 | Microsoft 365 | Audit log ready | BEC: inbox rules, forwarding, Global Admin, app consent, federation, mass download; Entra sign-ins: new country, impossible travel, stolen session, MFA fatigue, legacy auth |

``iocs.txt`` holds 16 case IOCs (defanged on purpose) of every type: IP, CIDR, IPv6, domain, URL, e-mail, hashes, paths, file and user.

## Checklist

**Case**
- [ ] The table lists 11 collections with the states above. WS02 can't be ticked; everything not analysed yet is ticked (9).
- [ ] The sidebar summary reads Extract + analyse: 3 · Analyse: 6 and shows the archive size.

**Sources and Settings**
- [ ] Sources has three sections: Linux / Unix (UAC), Windows (KAPE) and Microsoft 365 (scroll down). All on.
- [ ] Settings → Run: change "Collections analysed at the same time" (e.g. 2 or 4).

**IOCs**
- [ ] The panel shows 16 IOCs: 3 IP, 1 CIDR, 2 Domain, 2 URL, 1 Email, 1 MD5, 1 SHA1, 1 SHA256, 3 File, 1 User.

**Run**
- [ ] Click **Run 9 collection(s)**. Rows switch to Queued, Extracting, Analysing and Done, several at a time.
- [ ] uac-broken fails ("unsupported compression method"); the others finish. Done: 8 analysed, 1 failed.
- [ ] Run log: filter on one collection; tick "Warnings and errors only". Every line names its collection.
- [ ] Optional: run again with one row ticked and click its ■ to cancel it while it runs.

**Findings**
- [ ] All collections' findings in one grid, critical first, by time.
- [ ] Search ``203.0.113.45``: hits from Linux, Windows and M365 hosts.
- [ ] Host ``corp.example`` and Source ``ENTRA-SIGNIN``: impossible travel, stolen session, MFA fatigue.
- [ ] Severity ``LOW``: every finding is shown (the default, MEDIUM, hides SUSPICIOUS and LOW).

**Case summary (Level2\CaseSummary.txt)**
- [ ] Lateral movement: WS01 → DC01, WS01 → FS01 (RDP/network logons) and web01 → db01 → app01 … (scp).
- [ ] *Sources logging on to several hosts*: 203.0.113.45 → Linux hosts, WS01 and corp.example.

**Case report**
- [ ] Title is the case name; the bottom line is drafted from the findings.
- [ ] Export → HTML, Word (.docx), RTF and case tracker (.xlsx): each opens.

**IOC search and discovered IOCs, without re-analysing**
- [ ] IOCs: add ``203.0.113.46`` (cfo's attacker IP in M365), **Save to case**, then **Search analysed collections**. New hits on corp.example.
- [ ] **Load discovered**: indicators found in findings that aren't in the list yet are added at the bottom.

**Re-analyse**
- [ ] Case: tick only web01 (Analysed) and run. Its earlier results move to ``Level2\_previous\``.

**Output folders**
- [ ] ``Processed\uac-…\``: Normalized_*.csv and ProcessedBodyFile.csv. ``Processed\M365\``: Normalized_UAL.csv and Normalized_ENTRA.csv.
- [ ] ``Level2\<collection>\``: QuickWins.rtf, Findings.csv, Logons.csv, IocHits.csv, host.txt. ``Level2\``: CaseSummary.txt, CaseFindings.csv, CaseTracker.xlsx, iocs_discovered.txt.

**Headless**
- [ ] ``CsirtTriage.exe --case <folder>\INC-4711 --list`` prints the collections table in the console.
$expected
"@
Set-Content -Path (Join-Path $Path 'TESTING.md') -Value $testing -Encoding utf8
Write-Host "Test case written to $case; checklist: $(Join-Path $Path 'TESTING.md')"

if ($Zip) {
    if (Test-Path $Zip) { Remove-Item $Zip -Force }
    # .NET instead of Compress-Archive, which trips over the "[root]" folder names in UAC collections
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory((Resolve-Path $Path).Path, [IO.Path]::GetFullPath($Zip), [IO.Compression.CompressionLevel]::Optimal, $false)
    Write-Host "Zipped: $Zip ($([math]::Round((Get-Item $Zip).Length / 1MB, 1)) MB)"
}
