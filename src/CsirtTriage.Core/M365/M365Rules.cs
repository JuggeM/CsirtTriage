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

    /// <summary>The built-in rules (also used for whatever rules.json leaves out).</summary>
    public static readonly M365Rules Default = new();

    private sealed class Dto
    {
        public string? SuspiciousUserAgents { get; set; }
        public List<string>? HiddenFolders { get; set; }
        public string? RuleKeywords { get; set; }
        public List<string>? PrivilegedRoles { get; set; }
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
        };
    }
}
