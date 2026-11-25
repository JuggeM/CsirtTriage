using CsirtTriage.Core.Kape;

namespace CsirtTriage.Core.M365;

/// <summary>
/// Account takeover patterns in Entra ID sign-in log exports, per account.
/// Built for the usual case of a few exported accounts: each account's normal
/// country is learnt from its own successful sign-ins, and sign-ins that
/// deviate from it are reported. All findings have source ENTRA-SIGNIN.
/// </summary>
public sealed class EntraSignInAnalyser
{
    public const string Source = "ENTRA-SIGNIN";

    // Codes where the password was right but something after it stopped the sign-in
    private static readonly HashSet<string> MfaRequired = new() { "50074", "50076", "50079" };
    private const string MfaDenied = "500121";
    private const string CaBlocked = "53003";
    private static readonly HashSet<string> BadPassword = new() { "50126", "50053", "50055", "50057" };

    private readonly M365Config _cfg;
    private readonly M365Rules _rules;
    private readonly AnalysisContext _ctx;
    private readonly List<EntraSignIn> _all = new();

    public EntraSignInAnalyser(M365Config config, M365Rules rules, AnalysisContext ctx)
    {
        _cfg = config;
        _rules = rules;
        _ctx = ctx;
    }

    public void See(EntraSignIn s)
    {
        if (!_ctx.InDateRange(s.TimeUtc) || s.User.Length == 0) return;
        _all.Add(s);
        if (s.Succeeded && s.Ip.Length > 0)
            _ctx.RecordLogon(s.User, "M365", "", s.Ip, s.Interactive ? "Sign-in log" : "Sign-in log (non-interactive)", s.TimeUtc);
    }

    public void Complete()
    {
        foreach (var user in _all.GroupBy(s => s.User, StringComparer.OrdinalIgnoreCase))
            Analyse(user.Key, user.Where(s => s.TimeUtc.HasValue).OrderBy(s => s.TimeUtc).ToList());
    }

    private void Analyse(string user, List<EntraSignIn> list)
    {
        var ok = list.Where(s => s.Succeeded).ToList();
        var home = ok.Where(s => s.Country.Length > 0).GroupBy(s => s.Country, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => g.Count()).Select(g => g.Key).FirstOrDefault() ?? "";

        // New country: the first successful sign-in from each country other than the usual one
        if (home.Length > 0)
            foreach (var g in ok.Where(s => s.Country.Length > 0 && !s.Country.Equals(home, StringComparison.OrdinalIgnoreCase))
                                .GroupBy(s => s.Country, StringComparer.OrdinalIgnoreCase))
            {
                var first = g.First();
                bool hosting = Hosting(first), single = first.SingleFactor;
                var flags = new List<string>();
                if (hosting) flags.Add($"hosting provider AS{first.Asn}");
                if (single) flags.Add("single-factor");
                if (!first.Interactive) flags.Add("non-interactive (token)");
                Add(hosting || single ? Severity.Critical : Severity.High, first, g.Last().TimeUtc, g.Count(), "New country",
                    $"Sign-in from a new country for {user}: {Where(first)} from {first.Ip} (usually {home})" +
                    (flags.Count > 0 ? $" — {string.Join(", ", flags)}" : ""),
                    Describe(first));
            }

        // Hosting / VPS providers in the usual country (the new-country finding covers the others)
        foreach (var g in ok.Where(s => Hosting(s) && (home.Length == 0 || s.Country.Equals(home, StringComparison.OrdinalIgnoreCase)))
                            .GroupBy(s => (s.Asn, s.Ip)))
            Add(Severity.High, g.First(), g.Last().TimeUtc, g.Count(), "Hosting provider",
                $"Sign-in for {user} from a hosting/VPS provider: {g.Key.Ip} (AS{g.Key.Asn}, {Where(g.First())})", Describe(g.First()));

        // Impossible travel: consecutive successful sign-ins in different countries too close together
        var seenPairs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < ok.Count; i++)
        {
            var a = ok[i - 1]; var b = ok[i];
            if (a.Country.Length == 0 || b.Country.Length == 0 || a.Country.Equals(b.Country, StringComparison.OrdinalIgnoreCase)) continue;
            var gap = b.TimeUtc!.Value - a.TimeUtc!.Value;
            if (gap.TotalHours > _cfg.ImpossibleTravelHours) continue;
            if (!seenPairs.Add($"{a.Country}>{b.Country}")) continue;
            Add(Severity.High, a, b.TimeUtc, 2, "Impossible travel",
                $"Impossible travel for {user}: {Where(a)} ({a.Ip}) at {a.TimeUtc:HH:mm} and {Where(b)} ({b.Ip}) at {b.TimeUtc:HH:mm} UTC, {Minutes(gap)} apart",
                $"{Describe(a)} → {Describe(b)}");
        }

        // One session used from two countries: a session token replayed elsewhere (adversary-in-the-middle)
        foreach (var g in ok.Where(s => s.SessionId.Length > 0 && s.Country.Length > 0).GroupBy(s => s.SessionId, StringComparer.OrdinalIgnoreCase))
        {
            var countries = g.Select(s => s.Country).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (countries.Count < 2) continue;
            var firstOther = g.First(s => !s.Country.Equals(g.First().Country, StringComparison.OrdinalIgnoreCase));
            Add(Severity.High, g.First(), g.Last().TimeUtc, g.Count(), "Session in two countries",
                $"Session of {user} used from {string.Join(" and ", countries)} — possible stolen session token (AiTM): " +
                $"{g.First().Ip} then {firstOther.Ip}{(firstOther.Interactive ? "" : " (non-interactive)")}",
                $"Session ID {g.Key}; IPs {string.Join(", ", g.Select(s => s.Ip).Distinct())}");
        }

        // Legacy protocols (no MFA) and scripted clients
        foreach (var g in list.Where(s => _rules.LegacyClientApps.Contains(s.ClientApp)).GroupBy(s => (s.ClientApp, s.Ip, s.Succeeded)))
            Add(g.Key.Succeeded ? Severity.High : Severity.Medium, g.First(), g.Last().TimeUtc, g.Count(), "Legacy authentication",
                $"{(g.Key.Succeeded ? "Sign-in" : "Failed sign-in")} for {user} with legacy client {g.Key.ClientApp} (no MFA) from {g.Key.Ip} ({Where(g.First())})",
                Describe(g.First()));
        // (sign-ins with a legacy client are reported above; their user agent is usually BAV2ROPC)
        foreach (var g in list.Where(s => s.UserAgent.Length > 0 && !_rules.LegacyClientApps.Contains(s.ClientApp)
                                          && _rules.SuspiciousUserAgents.IsMatch(s.UserAgent))
                              .GroupBy(s => (Tool: _rules.SuspiciousUserAgents.Match(s.UserAgent).Value, s.Ip)))
            Add(g.Any(s => s.Succeeded) ? Severity.High : Severity.Medium, g.First(), g.Last().TimeUtc, g.Count(), "Scripted client",
                $"Sign-in{(g.Any(s => s.Succeeded) ? "" : " attempt")} for {user} with a scripted client ({g.Key.Tool}) from {g.Key.Ip} ({Where(g.First())})",
                $"User agent: {g.First().UserAgent}");

        // Password right, stopped by MFA; MFA prompts denied (fatigue); then a success
        foreach (var g in list.Where(s => MfaRequired.Contains(s.ErrorCode) && !ok.Any(o => o.Ip == s.Ip)).GroupBy(s => s.Ip))
            Add(Severity.High, g.First(), g.Last().TimeUtc, g.Count(), "Password known",
                $"Correct password for {user} from {g.Key} ({Where(g.First())}), stopped by the MFA requirement — the password is likely known to someone else",
                $"Error {g.First().ErrorCode}: {g.First().FailureReason}");
        foreach (var g in list.Where(s => s.ErrorCode == MfaDenied).GroupBy(s => s.Ip).Where(g => g.Count() >= _cfg.MfaFatigueThreshold))
        {
            var last = g.Last().TimeUtc!.Value;
            var after = ok.FirstOrDefault(s => s.TimeUtc >= last && s.TimeUtc <= last.AddHours(1) && s.Ip == g.Key);
            Add(after != null ? Severity.Critical : Severity.High, g.First(), after?.TimeUtc ?? last, g.Count(), "MFA fatigue",
                after != null
                    ? $"MFA fatigue succeeded: {g.Count()} MFA prompt(s) for {user} denied or failed from {g.Key} ({Where(g.First())}), then a successful sign-in at {after.TimeUtc:HH:mm} UTC"
                    : $"MFA fatigue: {g.Count()} MFA prompt(s) for {user} denied or failed from {g.Key} ({Where(g.First())})",
                $"Error {MfaDenied}: {g.First().FailureReason}");
        }

        // Brute force, and brute force that succeeded
        foreach (var g in list.Where(s => BadPassword.Contains(s.ErrorCode)).GroupBy(s => s.Ip).Where(g => g.Count() >= _cfg.BruteForceThreshold))
        {
            var last = g.Last().TimeUtc!.Value;
            var after = ok.FirstOrDefault(s => s.TimeUtc >= last && s.Ip == g.Key);
            Add(after != null ? Severity.Critical : Severity.Medium, g.First(), after?.TimeUtc ?? last, g.Count(), "Brute force",
                after != null
                    ? $"Brute force succeeded: {user} signed in from {g.Key} after {g.Count()} failed attempt(s)"
                    : $"Brute force: {g.Count()} failed sign-in(s) for {user} from {g.Key}, no success from that IP",
                $"{Where(g.First())}; error {g.First().ErrorCode}");
        }

        // Blocked by Conditional Access, and risky sign-ins
        foreach (var g in list.Where(s => s.ErrorCode == CaBlocked || s.ConditionalAccess.Equals("Failure", StringComparison.OrdinalIgnoreCase)).GroupBy(s => s.Ip))
            Add(Severity.Medium, g.First(), g.Last().TimeUtc, g.Count(), "Conditional Access",
                $"Sign-in for {user} from {g.Key} ({Where(g.First())}) blocked by Conditional Access (the password was accepted)",
                Describe(g.First()));
        foreach (var g in list.Where(s => s.RiskLevel is "high" or "High" or "medium" or "Medium").GroupBy(s => (s.Ip, Risk: s.RiskLevel.ToLowerInvariant())))
            Add(g.Key.Risk == "high" ? Severity.High : Severity.Medium, g.First(), g.Last().TimeUtc, g.Count(), "Risky sign-in",
                $"Entra ID rated sign-ins for {user} from {g.Key.Ip} as {g.Key.Risk} risk", Describe(g.First()));
    }

    private bool Hosting(EntraSignIn s) => s.Asn.Length > 0 && _rules.HostingAsns.Contains(s.Asn.Trim().TrimStart('A', 'S', 'a', 's'));

    private void Add(Severity sev, EntraSignIn first, DateTime? last, int count, string category, string text, string detail) =>
        _ctx.Add(new Finding
        {
            Severity = sev, TimeUtc = first.TimeUtc, LastUtc = last != first.TimeUtc ? last : null, Count = Math.Max(1, count),
            Source = Source, Category = category, Text = text, Detail = detail, Artifact = System.IO.Path.GetFileName(first.File),
        });

    private static string Where(EntraSignIn s) => s.Location.Length > 0 ? s.Location : s.Country.Length > 0 ? s.Country : "unknown location";

    private static string Minutes(TimeSpan t) => t.TotalMinutes < 90 ? $"{(int)t.TotalMinutes} min" : $"{t.TotalHours:0.#} h";

    private static string Describe(EntraSignIn s)
    {
        var parts = new List<string>();
        void P(string label, string value) { if (!string.IsNullOrWhiteSpace(value)) parts.Add($"{label} {value}"); }
        P("app", s.Application); P("client", s.ClientApp); P("auth", s.AuthRequirement); P("MFA", s.MfaMethod);
        P("CA", s.ConditionalAccess); P("AS", s.Asn); P("OS", s.Os); P("browser", s.Browser);
        P("managed", s.Managed); P("compliant", s.Compliant);
        if (!s.Interactive) parts.Add("non-interactive");
        return string.Join("; ", parts);
    }
}
