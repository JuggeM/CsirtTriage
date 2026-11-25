using System.Text.RegularExpressions;
using CsirtTriage.Core.Kape;

namespace CsirtTriage.Core.M365;

/// <summary>
/// Business e-mail compromise and account takeover patterns in the unified
/// audit log. Feed every record to <see cref="See"/>, then call
/// <see cref="Complete"/> for the patterns that need all records (brute
/// force, spray, bursts). Sources (the Source column of a finding):
///   M365-SIGNIN     Entra ID sign-ins (UserLoggedIn / UserLoginFailed)
///   M365-MAILBOX    inbox rules, forwarding, mailbox permissions, transport rules, audit settings, eDiscovery
///   M365-DIRECTORY  roles, MFA, passwords, users, app consent and credentials, domains, conditional access
///   M365-FILES      SharePoint / OneDrive downloads and sharing
///   M365-MAILACCESS MailItemsAccessed volume
/// </summary>
public sealed class UalAnalyser
{
    public const string SignIn = "M365-SIGNIN", Mailbox = "M365-MAILBOX", Directory = "M365-DIRECTORY",
                        Files = "M365-FILES", MailAccess = "M365-MAILACCESS";

    private readonly M365Config _cfg;
    private readonly M365Rules _rules;
    private readonly AnalysisContext _ctx;
    private readonly FindingAggregator _agg = new();
    private readonly HashSet<string> _tenantDomains = new(StringComparer.OrdinalIgnoreCase);

    // Sign-ins: per (user, ip) failures then success; per ip the accounts tried; per user the IPs per day
    private readonly Dictionary<(string User, string Ip), (int Failed, DateTime? First, DateTime? Last)> _failed = new();
    private readonly Dictionary<string, (HashSet<string> Users, int Count, DateTime? First, DateTime? Last)> _failedByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string User, DateTime Day), HashSet<string>> _ipsPerDay = new();
    private readonly Dictionary<(string User, DateTime Hour), (int Count, string Ip)> _downloads = new();
    private readonly Dictionary<(string User, DateTime Hour), (int Count, HashSet<string> Ips)> _mailItems = new();

    public UalAnalyser(M365Config config, M365Rules rules, AnalysisContext ctx)
    {
        _cfg = config;
        _rules = rules;
        _ctx = ctx;
    }

    /// <summary>The tenant's own mail domains (from the accounts in the log), to tell external forwarding apart.</summary>
    public IReadOnlyCollection<string> TenantDomains => _tenantDomains;

    public void See(UalRecord r)
    {
        if (!_ctx.InDateRange(r.TimeUtc)) return;
        if (Domain(r.User) is { Length: > 0 } domain) _tenantDomains.Add(domain);

        var op = r.Operation;
        if (op is "UserLoggedIn" or "UserLoginFailed") { if (_cfg.AnalyseSignIns) SignInRecord(r); return; }
        if (op is "MailItemsAccessed") { if (_cfg.AnalyseMailAccess) MailItems(r); return; }
        if (r.Workload is "SharePoint" or "OneDrive") { if (_cfg.AnalyseFiles) FileRecord(r); return; }
        if (r.Workload is "Exchange" || op.Contains('-')) { if (_cfg.AnalyseMailbox) MailboxRecord(r); return; }
        if (r.Workload is "AzureActiveDirectory" || op.EndsWith('.')) { if (_cfg.AnalyseDirectory) DirectoryRecord(r); }
    }

    // ── Sign-ins ─────────────────────────────────────────────────────
    private void SignInRecord(UalRecord r)
    {
        var user = r.User;
        var ip = r.ClientIp;
        if (r.Operation == "UserLoginFailed")
        {
            if (ip.Length == 0) return;
            var k = (user.ToLowerInvariant(), ip);
            var f = _failed.GetValueOrDefault(k);
            _failed[k] = (f.Failed + 1, f.First ?? r.TimeUtc, r.TimeUtc);
            var b = _failedByIp.GetValueOrDefault(ip);
            b.Users ??= new(StringComparer.OrdinalIgnoreCase);
            b.Users.Add(user);
            _failedByIp[ip] = (b.Users, b.Count + 1, b.First ?? r.TimeUtc, r.TimeUtc);
            return;
        }

        // Successful sign-in
        if (ip.Length > 0)
        {
            _ctx.RecordLogon(user, "M365", "", ip, "Audit log (UserLoggedIn)", r.TimeUtc);
            if (r.TimeUtc is DateTime t)
            {
                var dk = (user.ToLowerInvariant(), t.Date);
                if (!_ipsPerDay.TryGetValue(dk, out var set)) _ipsPerDay[dk] = set = new(StringComparer.OrdinalIgnoreCase);
                set.Add(ip);
            }
            var key = (user.ToLowerInvariant(), ip);
            if (_failed.TryGetValue(key, out var before) && before.Failed >= _cfg.BruteForceThreshold)
            {
                _agg.Add($"bfok|{key}", Severity.Critical, r.TimeUtc, SignIn, "Brute force succeeded",
                    $"Brute force succeeded: {user} signed in from {ip} after {before.Failed} failed attempt(s) since {Fmt(before.First)} UTC",
                    UaDetail(r), r.File);
                _failed.Remove(key);
            }
        }
        if (r.UserAgent.Length > 0 && _rules.SuspiciousUserAgents.Match(r.UserAgent) is { Success: true } m)
        {
            var legacy = m.Value.Equals("BAV2ROPC", StringComparison.OrdinalIgnoreCase);
            _agg.Add($"ua|{user}|{ip}|{m.Value}", Severity.High, r.TimeUtc, SignIn, legacy ? "Legacy authentication sign-in" : "Scripted sign-in",
                legacy
                    ? $"Legacy authentication (ROPC, no MFA) sign-in: {user} from {(ip.Length > 0 ? ip : "unknown IP")}"
                    : $"Sign-in with a scripted client ({m.Value}): {user} from {(ip.Length > 0 ? ip : "unknown IP")}",
                $"User agent: {r.UserAgent}", r.File);
        }
    }

    // ── Exchange ─────────────────────────────────────────────────────
    private static readonly string[] ForwardParams = { "ForwardTo", "ForwardAsAttachmentTo", "RedirectTo" };

    private void MailboxRecord(UalRecord r)
    {
        var op = r.Operation;
        var who = r.User;
        switch (op)
        {
            case "New-InboxRule":
            case "Set-InboxRule":
            case "UpdateInboxRules":
                InboxRule(r);
                return;
            case "Set-Mailbox" when ForwardingTarget(r).Length > 0:
                MailboxForwarding(r);
                return;
            case "Add-MailboxPermission":
                Add(Severity.Medium, r, Mailbox, "Mailbox permission",
                    $"Mailbox permission {r.Param("AccessRights")} on {r.Param("Identity")} granted to {r.Param("User")} by {who}");
                return;
            case "Add-RecipientPermission":
                Add(Severity.Medium, r, Mailbox, "Mailbox permission",
                    $"{r.Param("AccessRights")} permission on {r.Param("Identity")} granted to {r.Param("Trustee")} by {who}");
                return;
            case "Add-MailboxFolderPermission":
                Add(Severity.Suspicious, r, Mailbox, "Mailbox permission",
                    $"Folder permission {r.Param("AccessRights")} on {r.Param("Identity")} for {r.Param("User")} by {who}");
                return;
            case "New-TransportRule":
            case "Set-TransportRule":
            {
                var redirect = new[] { "RedirectMessageTo", "BlindCopyTo", "CopyTo", "AddToRecipients" }
                    .Select(p => (p, v: r.Param(p))).Where(x => x.v.Length > 0).ToList();
                Add(redirect.Count > 0 ? Severity.High : Severity.Medium, r, Mailbox, "Transport rule",
                    $"Transport rule '{FirstOf(r.Param("Name"), r.Param("Identity"))}' {(op.StartsWith("New") ? "created" : "changed")} by {who}" +
                    (redirect.Count > 0 ? $": {string.Join(", ", redirect.Select(x => $"{x.p} {x.v}"))}" : ""));
                return;
            }
            case "Set-AdminAuditLogConfig" when r.Param("UnifiedAuditLogIngestionEnabled").Equals("False", StringComparison.OrdinalIgnoreCase):
                Add(Severity.Critical, r, Mailbox, "Audit logging disabled", $"Unified audit logging switched off by {who}");
                return;
            case "Set-Mailbox" when r.Param("AuditEnabled").Equals("False", StringComparison.OrdinalIgnoreCase):
                Add(Severity.High, r, Mailbox, "Audit logging disabled", $"Mailbox auditing switched off for {r.Param("Identity")} by {who}");
                return;
            case "Set-MailboxAuditBypassAssociation" when r.Param("AuditBypassEnabled").Equals("True", StringComparison.OrdinalIgnoreCase):
                Add(Severity.High, r, Mailbox, "Audit logging disabled", $"Mailbox audit bypass enabled for {r.Param("Identity")} by {who}");
                return;
            case "Set-CASMailbox":
            {
                var enabled = new[] { "ImapEnabled", "PopEnabled", "EwsEnabled", "ActiveSyncEnabled" }
                    .Where(p => r.Param(p).Equals("True", StringComparison.OrdinalIgnoreCase)).ToList();
                if (enabled.Count > 0)
                    Add(Severity.Medium, r, Mailbox, "Mail protocol enabled",
                        $"{string.Join(", ", enabled)} switched on for {r.Param("Identity")} by {who} (legacy access to the mailbox)");
                return;
            }
            case "New-ComplianceSearch":
                Add(Severity.Medium, r, Mailbox, "eDiscovery", $"Content search '{r.Param("Name")}' created by {who}: {Short(r.Param("ContentMatchQuery"), 120)}");
                return;
            case "New-ComplianceSearchAction":
            {
                var action = r.Param("Export").Equals("True", StringComparison.OrdinalIgnoreCase) || r.Raw.Contains("Export") ? "export"
                           : r.Param("Purge").Equals("True", StringComparison.OrdinalIgnoreCase) ? "purge" : "action";
                Add(action == "action" ? Severity.Medium : Severity.High, r, Mailbox, "eDiscovery",
                    $"Content search {action} on '{r.Param("SearchName")}' by {who}");
                return;
            }
            case "SearchExportDownloaded":
                Add(Severity.High, r, Mailbox, "eDiscovery", $"Content search export downloaded by {who}");
                return;
        }
    }

    private void InboxRule(UalRecord r)
    {
        // OWA writes UpdateInboxRules with the rule in OperationProperties as JSON text; match on the raw record too
        string P(string name) => r.Param(name);
        var raw = r.Raw;
        var name = FirstOf(P("Name"), P("RuleName"), P("Identity"));
        var forward = ForwardParams.Select(p => P(p)).Where(v => v.Length > 0).ToList();
        if (r.Operation == "UpdateInboxRules" && Regex.IsMatch(raw, @"\b(Forward|Redirect)", RegexOptions.IgnoreCase))
        {
            // RuleActions is JSON text: [{"ActionType":"ForwardToRecipientsAction","Recipients":["x@y"]}]
            var to = Regex.Matches(P("RuleActions"), @"[\w.+-]+@[\w.-]+\.\w+").Select(m => m.Value).Distinct().ToList();
            forward.Add(to.Count > 0 ? string.Join(", ", to) : "(recipient not in the log)");
        }
        var move = P("MoveToFolder");
        if (move.Length == 0 && r.Operation == "UpdateInboxRules")
            move = _rules.HiddenFolders.FirstOrDefault(f => raw.Contains(f, StringComparison.OrdinalIgnoreCase)) ?? "";
        bool hidden = move.Length > 0 && _rules.HiddenFolders.Any(f => move.EndsWith(f, StringComparison.OrdinalIgnoreCase));
        bool delete = P("DeleteMessage").Equals("True", StringComparison.OrdinalIgnoreCase) || P("SoftDeleteMessage").Equals("True", StringComparison.OrdinalIgnoreCase)
                      || r.Operation == "UpdateInboxRules" && raw.Contains("\\\"Delete", StringComparison.OrdinalIgnoreCase);
        bool markRead = P("MarkAsRead").Equals("True", StringComparison.OrdinalIgnoreCase);
        var conditions = new[] { "SubjectContainsWords", "SubjectOrBodyContainsWords", "BodyContainsWords", "FromAddressContainsWords", "From" }
            .Select(p => P(p)).Where(v => v.Length > 0).ToList();
        bool keywords = conditions.Any(c => _rules.RuleKeywords.IsMatch(c)) || r.Operation == "UpdateInboxRules" && _rules.RuleKeywords.IsMatch(raw);

        var what = new List<string>();
        if (forward.Count > 0) what.Add($"forwards to {string.Join(", ", forward)}");
        if (delete) what.Add("deletes the message");
        if (move.Length > 0) what.Add($"moves to {move}");
        if (markRead) what.Add("marks as read");
        if (conditions.Count > 0) what.Add($"when {Short(string.Join("; ", conditions), 100)}");

        bool hides = hidden || delete;
        var sev = (forward.Count > 0 || hides) && keywords ? Severity.Critical
                : forward.Count > 0 || hides ? Severity.High
                : Severity.Suspicious;
        var verb = r.Operation == "Set-InboxRule" ? "changed" : "created";
        Add(sev, r, Mailbox, "Inbox rule",
            $"Inbox rule{(name.Length > 0 ? $" '{name}'" : "")} {verb} for {MailboxOf(r)}{(what.Count > 0 ? ": " + string.Join(", ", what) : "")}" +
            (r.ClientIp.Length > 0 ? $" (from {r.ClientIp})" : ""));
    }

    private static string ForwardingTarget(UalRecord r) => FirstOf(r.Param("ForwardingSmtpAddress"), r.Param("ForwardingAddress"));

    private void MailboxForwarding(UalRecord r)
    {
        var target = ForwardingTarget(r);
        var address = target.StartsWith("smtp:", StringComparison.OrdinalIgnoreCase) ? target[5..] : target;
        var external = Domain(address) is { Length: > 0 } d && !_tenantDomains.Contains(d);
        Add(external ? Severity.Critical : Severity.High, r, Mailbox, "Mailbox forwarding",
            $"Mailbox forwarding set on {FirstOf(r.Param("Identity"), MailboxOf(r))} to {address}" +
            (external ? " (external domain)" : "") +
            (r.Param("DeliverToMailboxAndForward").Equals("False", StringComparison.OrdinalIgnoreCase) ? ", no copy kept in the mailbox" : "") +
            $" by {r.User}");
    }

    private static string MailboxOf(UalRecord r)
    {
        // ObjectId is "tenant\user\rule id" for inbox rules; MailboxOwnerUPN for OWA
        var owner = r.Param("MailboxOwnerUPN");
        if (owner.Length > 0) return owner;
        var parts = r.ObjectId.Split('\\');
        if (parts.Length < 2) return r.User;
        // "jdoe" is the alias; the actor's address is the full name when it is the same mailbox
        return r.User.StartsWith(parts[1] + "@", StringComparison.OrdinalIgnoreCase) ? r.User : parts[1];
    }

    // ── Entra ID ─────────────────────────────────────────────────────
    private void DirectoryRecord(UalRecord r)
    {
        var op = r.Operation.TrimEnd('.');
        var who = r.User;
        var target = r.Targets.FirstOrDefault(t => t.Contains('@')) ?? r.Targets.FirstOrDefault(t => !Guid.TryParse(t, out _)) ?? r.ObjectId;
        string NewValue(string name) => r.Modified.TryGetValue(name, out var v) ? v.New.Trim('"', '[', ']', ' ') : "";

        switch (op)
        {
            case "Add member to role":
            {
                var role = FirstOf(NewValue("Role.DisplayName"), NewValue("Role.WellKnownObjectName"));
                var priv = _rules.PrivilegedRoles.Contains(role);
                Add(priv ? Severity.Critical : Severity.High, r, Directory, "Admin role",
                    $"{target} added to role '{(role.Length > 0 ? role : "unknown")}' by {who}");
                return;
            }
            case "Consent to application":
            {
                var admin = NewValue("ConsentContext.IsAdminConsent").Equals("True", StringComparison.OrdinalIgnoreCase);
                var app = r.Targets.FirstOrDefault(t => !Guid.TryParse(t, out _) && !t.Contains('@')) ?? r.ObjectId;
                var scopes = r.Modified.Where(kv => kv.Key.Contains("Permissions", StringComparison.OrdinalIgnoreCase)).Select(kv => kv.Value.New).FirstOrDefault() ?? "";
                Add(admin ? Severity.Critical : Severity.High, r, Directory, "App consent",
                    $"{(admin ? "Admin consent" : "Consent")} to application '{app}' by {who}" +
                    (scopes.Length > 0 ? $" — {Short(scopes, 140)}" : ""));
                return;
            }
            case "Add delegated permission grant":
            case "Add app role assignment to service principal":
            case "Add OAuth2PermissionGrant":
                Add(Severity.High, r, Directory, "App consent", $"{op}: '{target}' by {who}");
                return;
            case "Add service principal credentials":
            case "Update application – Certificates and secrets management":
            case "Update application - Certificates and secrets management":
                Add(Severity.High, r, Directory, "App credentials", $"Credentials added to application '{target}' by {who}");
                return;
            case "Add application":
            case "Add service principal":
                Add(Severity.Medium, r, Directory, "Application", $"{op}: '{target}' by {who}");
                return;
            case "Disable Strong Authentication":
                Add(Severity.High, r, Directory, "MFA", $"MFA disabled for {target} by {who}");
                return;
            case "User registered security info":
            case "User deleted security info":
            case "User changed default security info":
            case "Admin registered security info":
            case "Admin deleted security info":
                Add(Severity.Medium, r, Directory, "MFA", $"{op}: {target}{(who.Length > 0 && !who.Equals(target, StringComparison.OrdinalIgnoreCase) ? $" by {who}" : "")}");
                return;
            case "Update user" when r.Modified.Keys.Any(k => k.Contains("StrongAuthentication", StringComparison.OrdinalIgnoreCase)):
                Add(Severity.Medium, r, Directory, "MFA",
                    $"MFA settings changed for {target} by {who} ({string.Join(", ", r.Modified.Keys.Where(k => k.Contains("StrongAuthentication", StringComparison.OrdinalIgnoreCase)))})");
                return;
            case "Reset user password":
            case "Set force change user password":
                Add(Severity.Medium, r, Directory, "Password", $"Password reset for {target} by {who}");
                return;
            case "Change user password":
                Add(Severity.Suspicious, r, Directory, "Password", $"Password changed by {target}{(r.ClientIp.Length > 0 ? $" from {r.ClientIp}" : "")}");
                return;
            case "Add user":
                Add(Severity.Medium, r, Directory, "Account", $"Account {target} created by {who}");
                return;
            case "Delete user":
                Add(Severity.Medium, r, Directory, "Account", $"Account {target} deleted by {who}");
                return;
            case "Set domain authentication":
            case "Set federation settings on domain":
                Add(Severity.Critical, r, Directory, "Domain federation", $"{op}: {target} by {who} (federation changes can let an attacker sign in as any user)");
                return;
            case "Add domain to company":
            case "Verify domain":
                Add(Severity.High, r, Directory, "Domain", $"{op}: {target} by {who}");
                return;
        }
        if (op.Contains("conditional access policy", StringComparison.OrdinalIgnoreCase))
            Add(op.StartsWith("Delete", StringComparison.OrdinalIgnoreCase) ? Severity.High : Severity.Medium, r, Directory, "Conditional access",
                $"{op}: '{target}' by {who}");
    }

    // ── SharePoint / OneDrive ────────────────────────────────────────
    private void FileRecord(UalRecord r)
    {
        switch (r.Operation)
        {
            case "FileDownloaded":
            case "FileSyncDownloadedFull":
                if (r.TimeUtc is DateTime t)
                {
                    var k = (r.User.ToLowerInvariant(), new DateTime(t.Year, t.Month, t.Day, t.Hour, 0, 0, DateTimeKind.Utc));
                    var c = _downloads.GetValueOrDefault(k);
                    _downloads[k] = (c.Count + 1, c.Ip ?? r.ClientIp);
                }
                return;
            case "AnonymousLinkCreated":
                _agg.Add($"anon|{r.User}", Severity.Medium, r.TimeUtc, Files, "Anyone link",
                    $"'Anyone' sharing links created by {r.User}", "", r.File, Short(r.ObjectId, 160));
                return;
        }
    }

    // ── MailItemsAccessed ────────────────────────────────────────────
    private void MailItems(UalRecord r)
    {
        if (r.TimeUtc is not DateTime t) return;
        var k = (r.User.ToLowerInvariant(), new DateTime(t.Year, t.Month, t.Day, t.Hour, 0, 0, DateTimeKind.Utc));
        if (!_mailItems.TryGetValue(k, out var c)) c = (0, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        if (r.ClientIp.Length > 0) c.Ips.Add(r.ClientIp);
        _mailItems[k] = (c.Count + r.OperationCount, c.Ips);
    }

    // ── Patterns over all records ────────────────────────────────────
    public void Complete()
    {
        foreach (var ((user, ip), f) in _failed.Where(kv => kv.Value.Failed >= _cfg.BruteForceThreshold))
            _ctx.Add(new Finding
            {
                Severity = Severity.Medium, TimeUtc = f.First, LastUtc = f.Last, Count = f.Failed, Source = SignIn, Category = "Brute force",
                Text = $"Brute force: {f.Failed} failed sign-in(s) for {user} from {ip}, no success from that IP",
            });
        foreach (var (ip, b) in _failedByIp.Where(kv => kv.Value.Users.Count >= _cfg.SprayAccounts))
            _ctx.Add(new Finding
            {
                Severity = Severity.High, TimeUtc = b.First, LastUtc = b.Last, Count = b.Count, Source = SignIn, Category = "Password spray",
                Text = $"Password spray: {b.Users.Count} account(s) tried from {ip}, {b.Count} failed sign-in(s)",
                Detail = string.Join(", ", b.Users.Take(20)) + (b.Users.Count > 20 ? ", …" : ""),
            });
        foreach (var ((user, day), ips) in _ipsPerDay.Where(kv => kv.Value.Count >= _cfg.IpsPerUserPerDay))
            _ctx.Add(new Finding
            {
                Severity = Severity.Medium, TimeUtc = day, Source = SignIn, Category = "Many sign-in IPs",
                Text = $"{user} signed in from {ips.Count} different IP addresses on {day:yyyy-MM-dd}",
                Detail = string.Join(", ", ips.Take(20)),
            });
        foreach (var ((user, hour), c) in _downloads.Where(kv => kv.Value.Count >= _cfg.DownloadsPerHour))
            _ctx.Add(new Finding
            {
                Severity = Severity.High, TimeUtc = hour, LastUtc = hour.AddHours(1), Count = c.Count, Source = Files, Category = "Mass download",
                Text = $"Mass download: {user} downloaded {c.Count} file(s) between {hour:HH:mm} and {hour.AddHours(1):HH:mm} UTC" +
                       (string.IsNullOrEmpty(c.Ip) ? "" : $" (from {c.Ip})"),
            });
        foreach (var ((user, hour), c) in _mailItems.Where(kv => kv.Value.Count >= _cfg.MailItemsPerHour))
            _ctx.Add(new Finding
            {
                Severity = Severity.High, TimeUtc = hour, LastUtc = hour.AddHours(1), Count = c.Count, Source = MailAccess, Category = "Mail access burst",
                Text = $"{c.Count} mail item(s) of {user} accessed between {hour:HH:mm} and {hour.AddHours(1):HH:mm} UTC" +
                       (c.Ips.Count > 0 ? $" from {string.Join(", ", c.Ips.Take(5))}" : ""),
            });
        _ctx.AddRange(_agg.Flush((text, count, extras) => count > 1 && text.StartsWith("'Anyone'") ? $"{count} {text}" : text));
    }

    // ── Helpers ──────────────────────────────────────────────────────
    private void Add(Severity sev, UalRecord r, string source, string category, string text) =>
        _ctx.Add(new Finding
        {
            Severity = sev, TimeUtc = r.TimeUtc, Source = source, Category = category, Text = text,
            Detail = Short(ParamSummary(r), 400), Artifact = System.IO.Path.GetFileName(r.File),
        });

    private static string ParamSummary(UalRecord r) =>
        r.Parameters.Count > 0 ? string.Join("; ", r.Parameters.Select(kv => $"{kv.Key}={kv.Value}"))
        : r.Modified.Count > 0 ? string.Join("; ", r.Modified.Select(kv => $"{kv.Key}: {kv.Value.Old} → {kv.Value.New}"))
        : r.ClientIp.Length > 0 ? $"ClientIP={r.ClientIp}" : "";

    private static string UaDetail(UalRecord r) => r.UserAgent.Length > 0 ? $"User agent: {r.UserAgent}" : "";

    private static string Domain(string address)
    {
        int at = address.LastIndexOf('@');
        return at >= 0 && at + 1 < address.Length ? address[(at + 1)..].Trim().TrimEnd('>') : "";
    }

    private static string FirstOf(params string[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";
    private static string Short(string s, int max) => s.Length > max ? s[..(max - 1)] + "…" : s;
    private static string Fmt(DateTime? t) => t?.ToString("yyyy-MM-dd HH:mm:ss") ?? "?";
}
