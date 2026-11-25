<#
.SYNOPSIS
    Adds a synthetic Microsoft 365 unified audit log export (Purview audit
    search CSV) to a case folder: Uploads\M365\.

.DESCRIPTION
    A business e-mail compromise of the tenant corp.example, in the same
    timeline and from the same attacker IP (203.0.113.45) as the UAC and KAPE
    test cases, plus normal activity as noise. Two audit log files: the
    current Purview export layout (RecordId, CreationDate, RecordType,
    Operation, UserId, AuditData, …) and the classic one (CreationDate,
    UserIds, Operations, AuditData). Plus an Entra ID sign-in log export for
    the two accounts under investigation (jdoe, cfo): interactive,
    non-interactive and the AuthDetails file. All IPs and domains are from
    documentation ranges.

    Scenario                                          Expected finding
    6 accounts fail from 198.51.100.77                password spray (HIGH)
    12 failures then success for jdoe from .45        brute force succeeded (CRITICAL)
    cfo signs in with BAV2ROPC                         legacy authentication (HIGH)
    sales signs in from 5 IPs in a day                 many sign-in IPs (MEDIUM)
    inbox rule: invoice/payment → RSS Feeds, read      inbox rule (CRITICAL)
    OWA inbox rule forwarding cfo's mail               inbox rule (HIGH)
    mailbox forwarding to collect@evil-update.example  mailbox forwarding, external (CRITICAL)
    newsletter rule (normal)                           inbox rule (SUSPICIOUS)
    FullAccess on cfo's mailbox for jdoe               mailbox permission (MEDIUM)
    unified audit logging switched off                 audit logging disabled (CRITICAL)
    jdoe added to Global Administrator                 admin role (CRITICAL)
    consent to "Mail Sync Pro"                         app consent (HIGH)
    credentials added to a service principal           app credentials (HIGH)
    MFA method registered for jdoe                     MFA (MEDIUM)
    federation settings changed                        domain federation (CRITICAL)
    content search export                              eDiscovery (HIGH)
    120 files downloaded in one hour                   mass download (HIGH)
    3 'Anyone' links                                   Anyone link (MEDIUM)
    650 mail items accessed in one hour                mail access burst (HIGH)

    Entra sign-ins (source ENTRA-SIGNIN)
    jdoe: VPS in NL 15 min after a sign-in in SE      new country (CRITICAL), impossible travel (HIGH)
    jdoe: 12 failures then success from the VPS       brute force succeeded (CRITICAL)
    jdoe: morning session used from the VPS            session in two countries (HIGH)
    jdoe: password right, MFA required (DE)            password known (HIGH)
    jdoe: blocked by Conditional Access (NG)           conditional access (MEDIUM)
    cfo:  4 MFA denials then success (AWS, US)         MFA fatigue succeeded (CRITICAL), new country (CRITICAL)
    cfo:  IMAP4 from the VPS 4 min later (NL)          legacy authentication (HIGH), new country (CRITICAL), impossible travel (HIGH)
    cfo:  python-requests with the token               scripted client (HIGH)

.PARAMETER CaseFolder
    Case folder to add Uploads\M365 to (created if needed).
#>
param([Parameter(Mandatory)] [string] $CaseFolder)
$ErrorActionPreference = 'Stop'

$dir = Join-Path (Join-Path $CaseFolder 'Uploads') 'M365'
New-Item -ItemType Directory -Force $dir | Out-Null
$org = 'f2b1c9a4-0000-4000-8000-00000000c0de'
$base = [datetime]::new(2026, 11, 1, 0, 0, 0, [DateTimeKind]::Utc)
$records = [System.Collections.Generic.List[object]]::new()
$recordTypes = @{ AzureActiveDirectory = 15; Exchange = 1; SharePoint = 6; OneDrive = 7; ExchangeItem = 2 }

# The leading comma keeps a one-element list a list (PowerShell unwraps it otherwise)
function NameValues([hashtable] $h) { ,@($h.GetEnumerator() | Sort-Object Name | ForEach-Object { [ordered]@{ Name = $_.Name; Value = [string]$_.Value } }) }
function Rec([datetime] $t, [string] $op, [string] $workload, [string] $user, [hashtable] $extra = @{}, [int] $recordType = 0) {
    $a = [ordered]@{
        CreationTime = $t.ToString('yyyy-MM-ddTHH:mm:ss')
        Id = [guid]::NewGuid().ToString()
        Operation = $op
        OrganizationId = $org
        RecordType = $(if ($recordType) { $recordType } else { $recordTypes[$workload] })
        ResultStatus = 'Success'
        UserKey = $user
        UserType = 0
        Version = 1
        Workload = $workload
        UserId = $user
    }
    foreach ($k in $extra.Keys) { $a[$k] = $extra[$k] }
    $script:records.Add([pscustomobject]@{ Time = $t; Op = $op; User = $user; Workload = $workload; Json = ($a | ConvertTo-Json -Depth 8 -Compress) })
}
function SignIn([datetime] $t, [string] $user, [string] $ip, [bool] $ok = $true, [string] $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36') {
    $x = @{
        ClientIP = $ip; ActorIpAddress = $ip; ObjectId = '00000002-0000-0ff1-ce00-000000000000'
        AzureActiveDirectoryEventType = 1
        ExtendedProperties = NameValues @{ UserAgent = $ua; RequestType = 'OAuth2:Authorize'; ResultStatusDetail = $(if ($ok) { 'Redirect' } else { 'Success' }) }
        ErrorNumber = $(if ($ok) { '0' } else { '50126' })
    }
    if (-not $ok) { $x.LogonError = 'InvalidUserNameOrPassword' }
    Rec $t $(if ($ok) { 'UserLoggedIn' } else { 'UserLoginFailed' }) 'AzureActiveDirectory' $user $x
    if (-not $ok) { $script:records[-1].Json = $script:records[-1].Json.Replace('"ResultStatus":"Success"', '"ResultStatus":"Failed"') }
}
function Cmdlet([datetime] $t, [string] $op, [string] $user, [string] $ip, [hashtable] $params, [string] $objectId = '') {
    Rec $t $op 'Exchange' $user @{ ClientIP = "${ip}:51234"; ObjectId = $objectId; Parameters = (NameValues $params); OrganizationName = 'corp.onmicrosoft.com'; OriginatingServer = 'AM0PR01MB0001 (15.20.7000.000)' }
}
function EntraOp([datetime] $t, [string] $op, [string] $actor, [string[]] $targets, [hashtable] $modified = @{}) {
    $mods = @($modified.GetEnumerator() | ForEach-Object { [ordered]@{ Name = $_.Name; NewValue = [string]$_.Value; OldValue = '' } })
    Rec $t $op 'AzureActiveDirectory' $actor @{
        ObjectId = $targets[0]; ActorIpAddress = '203.0.113.45'; AzureActiveDirectoryEventType = 1
        Target = @($targets | ForEach-Object { [ordered]@{ ID = $_; Type = 2 } })
        ModifiedProperties = $mods
    } 8
}

$users = 'jdoe', 'cfo', 'sales', 'hr', 'admin', 'it.support', 'reception' | ForEach-Object { "$_@corp.example" }

# ── Normal activity (noise) ───────────────────────────────────────────
foreach ($d in 0..3) {
    foreach ($u in $users) {
        SignIn $base.AddDays($d).AddHours(7).AddMinutes(([array]::IndexOf($users, $u)) * 3) $u '192.0.2.10'
        Rec $base.AddDays($d).AddHours(8).AddMinutes(10) 'FileAccessed' 'SharePoint' $u @{ ClientIP = '192.0.2.10'; ObjectId = "https://corp.sharepoint.com/sites/Team/Shared Documents/Plan-$d.docx"; SourceFileName = "Plan-$d.docx" }
        Rec $base.AddDays($d).AddHours(9) 'Send' 'Exchange' $u @{ ClientIP = '192.0.2.10' } 2
    }
}

# ── Attack ────────────────────────────────────────────────────────────
# Password spray from 198.51.100.77
foreach ($u in $users[1..6]) { foreach ($i in 0..1) { SignIn $base.AddHours(8).AddMinutes(([array]::IndexOf($users, $u)) * 2 + $i) $u '198.51.100.77' $false } }
# Brute force on jdoe, then success
foreach ($i in 0..11) { SignIn $base.AddHours(9).AddSeconds($i * 20) 'jdoe@corp.example' '203.0.113.45' $false }
SignIn $base.AddHours(9).AddMinutes(5) 'jdoe@corp.example' '203.0.113.45'
# Legacy authentication for cfo
SignIn $base.AddHours(9).AddMinutes(40) 'cfo@corp.example' '203.0.113.46' $true 'BAV2ROPC'
# sales from five IPs in one day
foreach ($i in 1..5) { SignIn $base.AddDays(1).AddHours(6 + $i) 'sales@corp.example' "198.51.100.$($i + 100)" }

# BEC inbox rule (cmdlet), OWA forward rule, mailbox forwarding, a normal rule
Cmdlet $base.AddHours(9).AddMinutes(12) 'New-InboxRule' 'jdoe@corp.example' '203.0.113.45' @{ Name = '..'; MoveToFolder = 'RSS Feeds'; MarkAsRead = 'True'; StopProcessingRules = 'True'; SubjectContainsWords = 'invoice;payment' } 'corp.onmicrosoft.com\jdoe\13748291746592534529'
Rec $base.AddHours(9).AddMinutes(45) 'UpdateInboxRules' 'Exchange' 'cfo@corp.example' @{
    ClientIPAddress = '203.0.113.46'; MailboxOwnerUPN = 'cfo@corp.example'
    OperationProperties = NameValues @{ RuleName = 'Sync'; RuleOperation = 'AddMailboxRule'; RuleActions = '[{"ActionType":"ForwardToRecipientsAction","Recipients":["collect@evil-update.example"]}]' }
} 2
Cmdlet $base.AddHours(9).AddMinutes(14) 'Set-Mailbox' 'jdoe@corp.example' '203.0.113.45' @{ Identity = 'jdoe@corp.example'; ForwardingSmtpAddress = 'smtp:collect@evil-update.example'; DeliverToMailboxAndForward = 'False' }
Cmdlet $base.AddDays(2).AddHours(10) 'New-InboxRule' 'hr@corp.example' '192.0.2.10' @{ Name = 'Newsletters'; MoveToFolder = 'Newsletters'; From = 'news@vendor.example' } 'corp.onmicrosoft.com\hr\1'
# Mailbox permission, audit off, eDiscovery export
Cmdlet $base.AddHours(9).AddMinutes(20) 'Add-MailboxPermission' 'admin@corp.example' '203.0.113.45' @{ Identity = 'cfo@corp.example'; User = 'jdoe@corp.example'; AccessRights = 'FullAccess' }
Cmdlet $base.AddHours(9).AddMinutes(50) 'Set-AdminAuditLogConfig' 'admin@corp.example' '203.0.113.45' @{ UnifiedAuditLogIngestionEnabled = 'False' }
Cmdlet $base.AddHours(10).AddMinutes(5) 'New-ComplianceSearchAction' 'admin@corp.example' '203.0.113.45' @{ SearchName = 'all-mail'; Export = 'True'; Format = 'FxStream' }

# Entra ID
EntraOp $base.AddHours(9).AddMinutes(16) 'Add member to role.' 'admin@corp.example' @('jdoe@corp.example') @{ 'Role.DisplayName' = 'Global Administrator'; 'Role.WellKnownObjectName' = 'CompanyAdministrator' }
EntraOp $base.AddHours(9).AddMinutes(18) 'Consent to application.' 'jdoe@corp.example' @('Mail Sync Pro', 'a1b2c3d4-0000-4000-8000-000000000001') @{ 'ConsentContext.IsAdminConsent' = 'False'; 'ConsentAction.Permissions' = 'Scope: Mail.Read Mail.Send offline_access' }
EntraOp $base.AddHours(9).AddMinutes(19) 'Add service principal credentials.' 'jdoe@corp.example' @('Mail Sync Pro')
EntraOp $base.AddHours(9).AddMinutes(8) 'User registered security info' 'jdoe@corp.example' @('jdoe@corp.example')
EntraOp $base.AddHours(11) 'Reset user password.' 'it.support@corp.example' @('reception@corp.example')
EntraOp $base.AddHours(10).AddMinutes(30) 'Set federation settings on domain.' 'jdoe@corp.example' @('corp.example') @{ IssuerUri = 'http://any.sts/16B45E3B' }

# SharePoint: mass download, Anyone links
foreach ($i in 0..119) {
    Rec $base.AddHours(10).AddSeconds($i * 25) 'FileDownloaded' 'SharePoint' 'jdoe@corp.example' @{ ClientIP = '203.0.113.45'; ObjectId = "https://corp.sharepoint.com/sites/Finance/Shared Documents/Q$($i % 4 + 1)/report-$i.xlsx"; SourceFileName = "report-$i.xlsx"; UserAgent = 'python-requests/2.31' }
}
foreach ($i in 1..3) {
    Rec $base.AddHours(10).AddMinutes(50 + $i) 'AnonymousLinkCreated' 'SharePoint' 'jdoe@corp.example' @{ ClientIP = '203.0.113.45'; ObjectId = "https://corp.sharepoint.com/sites/Finance/Shared Documents/salaries-$i.xlsx" }
}
# Mail access burst on cfo's mailbox (MailItemsAccessed is aggregated, OperationCount per record)
foreach ($i in 0..12) {
    Rec $base.AddHours(9).AddMinutes(22 + $i * 3) 'MailItemsAccessed' 'Exchange' 'cfo@corp.example' @{
        ClientIPAddress = '203.0.113.45'; OperationCount = 50; MailboxOwnerUPN = 'cfo@corp.example'
        OperationProperties = NameValues @{ MailAccessType = 'Bind'; IsThrottled = 'False' }
    } 50
}

# ── Write: current layout, plus the last day in the classic layout ───
$utf8 = New-Object System.Text.UTF8Encoding($false)
function Q([string] $s) { '"' + $s.Replace('"', '""') + '"' }
$sorted = $records | Sort-Object Time
$cut = $base.AddDays(3)
$current = $sorted | Where-Object { $_.Time -lt $cut }
$classic = $sorted | Where-Object { $_.Time -ge $cut }
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,AssociatedAdminUnitsNames')
foreach ($r in $current) {
    $lines.Add((@([guid]::NewGuid().ToString(), $r.Time.ToString('yyyy-MM-ddTHH:mm:ss.0000000Z'), $r.Workload, $r.Op, $r.User, $r.Json, '', '') | ForEach-Object { Q $_ }) -join ',')
}
[IO.File]::WriteAllText((Join-Path $dir 'Audit_Search_INC-4711_20261104.csv'), ($lines -join "`r`n") + "`r`n", $utf8)
$lines.Clear()
$lines.Add('CreationDate,UserIds,Operations,AuditData')
foreach ($r in $classic) { $lines.Add((@($r.Time.ToString('M/d/yyyy h:mm:ss tt', [Globalization.CultureInfo]::InvariantCulture), $r.User, $r.Op, $r.Json) | ForEach-Object { Q $_ }) -join ',') }
[IO.File]::WriteAllText((Join-Path $dir 'AuditLog_classic_20261104.csv'), ($lines -join "`r`n") + "`r`n", $utf8)

# ── Entra ID sign-in log export for the two accounts under investigation ──
# As downloaded from Entra admin center → Sign-in logs (filtered on the user), CSV.
$signInHeader = 'Date (UTC),Request ID,User agent,Correlation ID,User ID,User,Username,User type,Cross tenant access type,Incoming token type,Authentication Protocol,Unique token identifier,Original transfer method,Client credential type,Application,Application ID,Resource,Resource ID,Resource tenant ID,Home tenant ID,Home tenant name,IP address,Location,Status,Sign-in error code,Failure reason,Client app,Device ID,Browser,Operating System,Compliant,Managed,Join Type,Multifactor authentication result,Multifactor authentication auth method,Multifactor authentication auth detail,Authentication requirement,Sign-in identifier,Session ID,IP address (seen by resource),Through Global Secure Access,Global Secure Access IP address,Autonomous system number,Flagged for review,Token issuer type,Token issuer name,Latency,Conditional Access,Managed Identity type'
$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'
function SignInRow([datetime] $t, [string] $user, [string] $ip, [string] $location, [string] $asn, [string] $session,
                   [string] $status = 'Success', [string] $code = '0', [string] $reason = 'Other.', [string] $client = 'Browser',
                   [string] $auth = 'Multifactor authentication', [string] $ua = $chrome, [string] $ca = 'Success') {
    $mfa = if ($auth -like 'Multi*' -and $status -eq 'Success') { 'MFA requirement satisfied by claim in the token' } else { '' }
    $v = @($t.ToString('yyyy-MM-ddTHH:mm:ssZ'), [guid]::NewGuid(), $ua, [guid]::NewGuid(), [guid]::NewGuid(), ($user -split '@')[0], $user, 'Member', 'none', 'none',
           'none', [guid]::NewGuid(), 'none', 'none', 'OfficeHome', '4765445b-32c6-49b0-83e6-1d93765276ca', 'Office 365 Exchange Online', '00000002-0000-0ff1-ce00-000000000000',
           $org, $org, 'Corp', $ip, $location, $status, $code, $reason, $client, '', $(if ($ua -like 'Mozilla*') { 'Chrome 130.0' } else { '' }),
           $(if ($ua -like 'Mozilla*') { 'Windows10' } else { '' }), 'False', 'False', '', $mfa, '', '', $auth, $user, $session, $ip, 'False', '', $asn, 'False',
           'AzureAD', '', '120', $ca, '')
    ($v | ForEach-Object { Q ([string]$_) }) -join ','
}
$se = 'Stockholm, Stockholm, SE'; $nl = 'Amsterdam, Noord-Holland, NL'
$interactive = [System.Collections.Generic.List[string]]::new(); $interactive.Add($signInHeader)
$nonInteractive = [System.Collections.Generic.List[string]]::new(); $nonInteractive.Add($signInHeader)
foreach ($d in 0..3) {
    foreach ($u in 'jdoe@corp.example', 'cfo@corp.example') {
        $interactive.Add((SignInRow $base.AddDays($d).AddHours(7) $u '192.0.2.10' $se '3301' "sess-$u-day$d"))
        $nonInteractive.Add((SignInRow $base.AddDays($d).AddHours(13) $u '192.0.2.10' $se '3301' "sess-$u-day$d"))
    }
}
# jdoe: normal sign-in, brute force, then a sign-in from a VPS in NL 15 minutes later
$interactive.Add((SignInRow $base.AddHours(8).AddMinutes(50) 'jdoe@corp.example' '192.0.2.10' $se '3301' 'sess-jdoe-1'))
foreach ($i in 0..11) { $interactive.Add((SignInRow $base.AddHours(9).AddSeconds($i * 20) 'jdoe@corp.example' '203.0.113.45' $nl '14061' '' 'Failure' '50126' 'Error validating credentials due to invalid username or password.')) }
$interactive.Add((SignInRow $base.AddHours(9).AddMinutes(5) 'jdoe@corp.example' '203.0.113.45' $nl '14061' 'sess-jdoe-2'))
# jdoe's morning session token replayed from the attacker's server (AiTM)
$nonInteractive.Add((SignInRow $base.AddHours(10).AddMinutes(15) 'jdoe@corp.example' '203.0.113.45' $nl '14061' 'sess-jdoe-1'))
# jdoe: correct password from Germany, stopped by MFA; blocked by Conditional Access from Nigeria
$interactive.Add((SignInRow $base.AddDays(1).AddHours(3) 'jdoe@corp.example' '198.51.100.201' 'Frankfurt am Main, Hessen, DE' '3320' '' 'Interrupted' '50074' 'Strong Authentication is required.'))
$interactive.Add((SignInRow $base.AddDays(1).AddHours(4) 'jdoe@corp.example' '203.0.113.50' 'Lagos, Lagos, NG' '29465' '' 'Failure' '53003' 'Access has been blocked by Conditional Access policies.' 'Browser' 'Single-factor authentication' $chrome 'Failure'))
# cfo: MFA fatigue from AWS in the US, then success; IMAP from the VPS; a python script with the token
foreach ($i in 0..3) { $interactive.Add((SignInRow $base.AddHours(9).AddMinutes(30 + $i) 'cfo@corp.example' '198.51.100.200' 'Ashburn, Virginia, US' '14618' '' 'Failure' '500121' 'Authentication failed during strong authentication request.')) }
$interactive.Add((SignInRow $base.AddHours(9).AddMinutes(36) 'cfo@corp.example' '198.51.100.200' 'Ashburn, Virginia, US' '14618' 'sess-cfo-2'))
$interactive.Add((SignInRow $base.AddHours(9).AddMinutes(40) 'cfo@corp.example' '203.0.113.46' $nl '14061' 'sess-cfo-3' 'Success' '0' 'Other.' 'IMAP4' 'Single-factor authentication' 'BAV2ROPC'))
$nonInteractive.Add((SignInRow $base.AddHours(10) 'cfo@corp.example' '203.0.113.46' $nl '14061' 'sess-cfo-3' 'Success' '0' 'Other.' 'Mobile Apps and Desktop clients' 'Single-factor authentication' 'python-requests/2.31.0'))

[IO.File]::WriteAllText((Join-Path $dir 'InteractiveSignIns_2026-11-01_2026-11-04.csv'), ($interactive -join "`r`n") + "`r`n", $utf8)
[IO.File]::WriteAllText((Join-Path $dir 'NonInteractiveSignIns_2026-11-01_2026-11-04.csv'), ($nonInteractive -join "`r`n") + "`r`n", $utf8)
# The AuthDetails file comes with the download; CsirtTriage skips it
[IO.File]::WriteAllText((Join-Path $dir 'InteractiveSignIns_AuthDetails_2026-11-01_2026-11-04.csv'),
    "Date (UTC),Request ID,Authentication method,Authentication method detail,Succeeded,Result detail,Requirement`r`n" +
    ((Q $base.AddHours(7).ToString('yyyy-MM-ddTHH:mm:ssZ')) + ',' + (Q ([guid]::NewGuid())) + ',"Password","Password in the cloud","True","Correct password","Primary authentication"') + "`r`n", $utf8)

Write-Host "M365 test export written to $dir ($($current.Count) + $($classic.Count) records)"
