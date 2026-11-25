using System.Text.Json;
using System.Text.RegularExpressions;

namespace CsirtTriage.Core.M365;

/// <summary>
/// The "m365" section of rules.json: patterns the unified audit log analysis
/// uses. Missing entries fall back to the built-in defaults, so an older
/// rules.json without the section still works.
/// </summary>
public sealed class M365Rules
{
    /// <summary>Sign-in user agents of scripts, attack tools and legacy authentication.</summary>
    public Regex SuspiciousUserAgents { get; private init; } = DefaultUserAgents;
    /// <summary>Folders an inbox rule moves mail to so the user doesn't see it.</summary>
    public HashSet<string> HiddenFolders { get; private init; } = DefaultHiddenFolders;
    /// <summary>Words in inbox rule conditions that point at business e-mail compromise.</summary>
    public Regex RuleKeywords { get; private init; } = DefaultRuleKeywords;
    /// <summary>Admin roles whose assignment is critical.</summary>
    public HashSet<string> PrivilegedRoles { get; private init; } = DefaultPrivilegedRoles;
    /// <summary>Autonomous system numbers of hosting and VPS providers (sign-ins from servers, not homes or offices).</summary>
    public HashSet<string> HostingAsns { get; private init; } = DefaultHostingAsns;
    /// <summary>Entra "Client app" values of legacy protocols that can't do MFA.</summary>
    public HashSet<string> LegacyClientApps { get; private init; } = DefaultLegacyClientApps;

    private static readonly Regex DefaultUserAgents = new(
        @"BAV2ROPC|python-requests|python-urllib|Go-http-client|axios|curl/|Wget|okhttp|PostmanRuntime|aiohttp|libwww-perl|Java/|node-fetch|AADInternals|ROADtools|TokenTactics|GraphRunner|evilginx",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly HashSet<string> DefaultHiddenFolders = new(StringComparer.OrdinalIgnoreCase)
        { "RSS Feeds", "RSS Subscriptions", "Archive", "Conversation History", "Junk Email", "Deleted Items", "Notes", "Sync Issues" };
    private static readonly Regex DefaultRuleKeywords = new(
        @"invoice|payment|wire|transfer|bank|iban|swift|remittance|account details|password|credential|security|phish|hack|compromise|suspicious|helpdesk|it support|urgent|ceo|payroll",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly HashSet<string> DefaultPrivilegedRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        "Global Administrator", "Company Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
        "Security Administrator", "Exchange Administrator", "SharePoint Administrator", "Application Administrator",
        "Cloud Application Administrator", "User Administrator", "Authentication Administrator", "Hybrid Identity Administrator",
        "Conditional Access Administrator", "Compliance Administrator", "eDiscovery Manager",
    };

    private static readonly HashSet<string> DefaultHostingAsns = new(StringComparer.OrdinalIgnoreCase)
    {
        "14061",  // DigitalOcean
        "16509", "14618", // Amazon AWS
        "15169", "396982", // Google Cloud
        "24940",  // Hetzner
        "16276",  // OVH
        "63949",  // Linode / Akamai
        "20473",  // Vultr (Choopa)
        "9009",   // M247
        "212238", // Datacamp (CDN77)
        "60068",  // CDN77
        "51167",  // Contabo
        "197540", // netcup
        "36352",  // ColoCrossing
        "62240",  // Clouvider
        "209",    // Lumen (also used by VPS resellers)
        "8100",   // QuadraNet
        "46562",  // Performive
        "40021",  // Contabo US
        "399629", // BL Networks
        "212815", // Dyjix
    };
    private static readonly HashSet<string> DefaultLegacyClientApps = new(StringComparer.OrdinalIgnoreCase)
    {
        "IMAP4", "IMAP", "POP3", "POP", "Authenticated SMTP", "SMTP", "Exchange ActiveSync", "Exchange Online PowerShell",
        "Autodiscover", "Exchange Web Services", "MAPI Over HTTP", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)",
        "Reporting Web Services", "Other clients",
    };

    /// <summary>The built-in rules (also used for whatever rules.json leaves out).</summary>
    public static readonly M365Rules Default = new();

    private sealed class Dto
    {
        public string? SuspiciousUserAgents { get; set; }
        public List<string>? HiddenFolders { get; set; }
        public string? RuleKeywords { get; set; }
        public List<string>? PrivilegedRoles { get; set; }
        public List<string>? HostingAsns { get; set; }
        public List<string>? LegacyClientApps { get; set; }
    }
    private sealed class FileDto { public Dto? M365 { get; set; } }

    /// <summary>Reads the "m365" section of a rules file; defaults for whatever is missing or invalid.</summary>
    public static M365Rules Load(string path, Action<string>? warn = null)
    {
        Dto? d = null;
        try
        {
            if (File.Exists(path))
                d = JsonSerializer.Deserialize<FileDto>(File.ReadAllText(path), new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true,
                })?.M365;
        }
        catch (JsonException ex) { warn?.Invoke($"[WARN] rules.json m365 section not read ({ex.Message}); using defaults."); }
        if (d == null) return Default;

        Regex Rx(string? pattern, Regex fallback, string name)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return fallback;
            try { return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1)); }
            catch (ArgumentException ex) { warn?.Invoke($"[WARN] rules.json m365.{name} is not a valid pattern ({ex.Message}); using the default."); return fallback; }
        }
        return new M365Rules
        {
            SuspiciousUserAgents = Rx(d.SuspiciousUserAgents, Default.SuspiciousUserAgents, "suspiciousUserAgents"),
            HiddenFolders = d.HiddenFolders is { Count: > 0 } f ? new(f, StringComparer.OrdinalIgnoreCase) : Default.HiddenFolders,
            RuleKeywords = Rx(d.RuleKeywords, Default.RuleKeywords, "ruleKeywords"),
            PrivilegedRoles = d.PrivilegedRoles is { Count: > 0 } r ? new(r, StringComparer.OrdinalIgnoreCase) : Default.PrivilegedRoles,
            HostingAsns = d.HostingAsns is { Count: > 0 } a ? new(a.Select(x => x.Trim().TrimStart('A', 'S', 'a', 's')), StringComparer.OrdinalIgnoreCase) : Default.HostingAsns,
            LegacyClientApps = d.LegacyClientApps is { Count: > 0 } l ? new(l, StringComparer.OrdinalIgnoreCase) : Default.LegacyClientApps,
        };
    }
}
