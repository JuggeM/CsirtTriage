using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace CsirtTriage.Core;

/// <summary>One analyst-supplied indicator. Kind is one of <see cref="CaseIocs.KindOrder"/>.</summary>
public sealed record Ioc(string Kind, string Value, string Comment)
{
    /// <summary>Line as stored in iocs.txt; kinds that can't be inferred from the value keep their prefix.</summary>
    public string ToLine()
    {
        var v = Kind switch
        {
            "User" => "user:" + Value,
            "File" when !CaseIocs.LooksLikeFile(Value) => "file:" + Value,
            _ => Value,
        };
        return string.IsNullOrWhiteSpace(Comment) ? v : $"{v,-45}  # {Comment}";
    }
}

/// <summary>
/// The case IOC list (&lt;case&gt;\iocs.txt), shared by UAC and KAPE collections:
/// parsing of pasted or imported text, re-fanging, type detection, load/save.
///
/// Input is forgiving: one or more IOCs per line, separated by whitespace,
/// comma or semicolon; text after " #" is a comment for every IOC on that
/// line. Defanged forms (hxxp, [.], (dot), [:], [@]) are re-fanged. Kinds
/// that can't be told from the value need a prefix: user:alice, file:x.sh.
/// Absolute Unix and Windows paths and executable file names (evil.exe) are
/// recognised without a prefix. A line that yields no IOC is reported as
/// rejected; unrecognised tokens on a line that did yield one are ignored.
/// </summary>
public static class CaseIocs
{
    public const string FileName = "iocs.txt";
    public const string DiscoveredFileName = "iocs_discovered.txt";

    public static readonly string[] KindOrder =
        { "IP", "CIDR", "Domain", "URL", "Email", "MD5", "SHA1", "SHA256", "File", "User" };

    private static readonly Regex Hex = new(@"^[0-9a-fA-F]+$", RegexOptions.Compiled);
    private static readonly Regex Ipv4 = new(@"^\d{1,3}(?:\.\d{1,3}){3}$", RegexOptions.Compiled);
    private static readonly Regex DomainRx = new(
        @"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", RegexOptions.Compiled);
    private static readonly Regex EmailRx = new(@"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", RegexOptions.Compiled);
    private static readonly Regex UrlRx = new(@"^(?:https?|ftp)://[^\s/$.?#][^\s]*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex WinPathRx = new(@"^(?:[a-z]:\\|\\\\[^\\]|%[a-z_]+%\\)\S*", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex ExeLikeRx = new(
        @"^[^\\/\s:]+\.(?:exe|dll|ps1|bat|cmd|vbs|hta|scr|sys|msi|lnk|jar)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // "x.sh", "img.php": file names, not domains (use file:x.sh for those)
    private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "sh", "php", "py", "txt", "log", "conf", "so", "exe", "dll", "js", "html", "htm", "jsp",
        "asp", "aspx", "gz", "tar", "tgz", "json", "xml", "yml", "yaml", "bak", "ps1", "bat",
        "elf", "bin", "tmp", "csv", "ini", "cfg", "phtml", "pyc", "jar", "war", "zip", "out",
        "cmd", "vbs", "hta", "scr", "sys", "msi", "lnk", "7z", "rar",
    };

    /// <summary>True for values whose kind (File) is clear without a "file:" prefix.</summary>
    public static bool LooksLikeFile(string v) =>
        v.StartsWith('/') || WinPathRx.IsMatch(v) || ExeLikeRx.IsMatch(v);

    // ── Re-fang ──────────────────────────────────────────────────────
    public static string Refang(string s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? "";
        s = Regex.Replace(s, @"^h(?:xx|XX|\*\*|tt)p(s?)(?=\[?:)", "http$1", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"^fxp(?=\[?:)", "ftp", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}|\\\.", ".", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"\[\s*:\s*\]|\[:\/\/\]", m => m.Value.Contains("//") ? "://" : ":");
        s = Regex.Replace(s, @"\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)", "@", RegexOptions.IgnoreCase);
        return s;
    }

    // ── Classify one token ───────────────────────────────────────────
    /// <summary>Returns the IOC for a token, or null when it isn't one.</summary>
    public static Ioc? Classify(string token, string comment = "")
    {
        var raw = (token ?? "").Trim().Trim('"', '\'', '<', '>', '(', ')', '`');
        // Windows paths: "[.]" re-fanging and bracket trimming would damage them
        if (WinPathRx.IsMatch(raw)) return new Ioc("File", raw.TrimEnd(',', ';'), comment);

        var t = Refang(raw.Trim('[', ']'));
        t = t.TrimEnd(',', ';', '.');
        if (t.Length < 3) return null;

        // Explicit prefix: user:, file:, ip:, domain:, url:, hash:, md5:, sha1:, sha256:
        var pm = Regex.Match(t, @"^(?<p>user|account|file|path|ip|domain|host|url|hash|md5|sha1|sha256|email)\s*:\s*(?<v>.+)$",
            RegexOptions.IgnoreCase);
        if (pm.Success && !t.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            var p = pm.Groups["p"].Value.ToLowerInvariant();
            var v = pm.Groups["v"].Value.Trim();
            if (p is "user" or "account")
                return Regex.IsMatch(v, @"^[A-Za-z0-9_.\-$@\\]{1,64}$") ? new Ioc("User", v, comment) : null;
            if (p is "file" or "path")
                return v.Length >= 2 ? new Ioc("File", v, comment) : null;
            return Classify(v, comment);
        }

        if (UrlRx.IsMatch(t)) return new Ioc("URL", t, comment);

        // ip:port → ip
        var ipPort = Regex.Match(t, @"^(?<ip>\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$");
        if (ipPort.Success) t = ipPort.Groups["ip"].Value;
        if (EmailRx.IsMatch(t)) return new Ioc("Email", t.ToLowerInvariant(), comment);

        // CIDR
        var slash = t.IndexOf('/');
        if (slash > 0 && int.TryParse(t[(slash + 1)..], out var prefix) && IPAddress.TryParse(t[..slash], out var net))
        {
            int max = net.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix >= 0 && prefix <= max && (net.AddressFamily != AddressFamily.InterNetwork || Ipv4.IsMatch(t[..slash])))
                return prefix == max ? new Ioc("IP", net.ToString(), comment) : new Ioc("CIDR", $"{net}/{prefix}", comment);
        }

        // IP (v4 must be a dotted quad: IPAddress.TryParse accepts "1" and "1.2")
        if (IPAddress.TryParse(t, out var ip))
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork && Ipv4.IsMatch(t)) return new Ioc("IP", ip.ToString(), comment);
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && t.Contains(':')) return new Ioc("IP", ip.ToString(), comment);
        }

        // Hashes
        if (Hex.IsMatch(t))
            return t.Length switch
            {
                32 => new Ioc("MD5", t.ToLowerInvariant(), comment),
                40 => new Ioc("SHA1", t.ToLowerInvariant(), comment),
                64 => new Ioc("SHA256", t.ToLowerInvariant(), comment),
                _ => null,
            };

        // Absolute Unix path
        if (t.StartsWith('/') && t.Length > 1 && !t.Contains(' ')) return new Ioc("File", t, comment);
        // Executable file name (evil.exe, payload.ps1)
        if (ExeLikeRx.IsMatch(t)) return new Ioc("File", t, comment);

        // Domain (not a file name)
        var lower = t.ToLowerInvariant();
        if (DomainRx.IsMatch(lower))
        {
            var tld = lower[(lower.LastIndexOf('.') + 1)..];
            if (!FileExtensions.Contains(tld)) return new Ioc("Domain", lower, comment);
        }
        return null;
    }

    // ── Parse pasted / imported text ─────────────────────────────────
    public static (List<Ioc> Iocs, List<string> Rejected) Parse(string text)
    {
        var result = new List<Ioc>();
        var seen = new HashSet<(string, string)>();
        var rejected = new List<string>();

        foreach (var rawLine in (text ?? "").Split('\n'))
        {
            var line = rawLine.Trim().TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("//")) continue;

            // Comment: '#' preceded by whitespace (keeps URL fragments intact)
            string comment = "";
            var hash = Regex.Match(line, @"\s#\s?(?<c>.*)$");
            if (hash.Success)
            {
                comment = hash.Groups["c"].Value.Trim();
                line = line[..hash.Index].Trim();
            }

            bool any = false;
            foreach (var tok in Regex.Split(line, @"[\s,;|]+").Where(x => x.Length > 0))
            {
                var ioc = Classify(tok, comment);
                if (ioc == null) continue;
                any = true;
                if (seen.Add((ioc.Kind, ioc.Value.ToLowerInvariant()))) result.Add(ioc);
            }
            // Windows paths may contain spaces: try the whole line as one value
            if (!any && Classify(line, comment) is { } whole)
            {
                any = true;
                if (seen.Add((whole.Kind, whole.Value.ToLowerInvariant()))) result.Add(whole);
            }
            if (!any) rejected.Add(line.Length > 80 ? line[..77] + "..." : line);
        }
        return (result, rejected);
    }

    public static string Summary(IReadOnlyCollection<Ioc> iocs)
    {
        if (iocs.Count == 0) return "no IOCs";
        var parts = iocs.GroupBy(i => i.Kind).OrderBy(g => Array.IndexOf(KindOrder, g.Key)).Select(g => $"{g.Count()} {g.Key}");
        return $"{iocs.Count} IOC(s): {string.Join(", ", parts)}";
    }

    // ── File I/O ─────────────────────────────────────────────────────
    public static string PathFor(string caseFolder) => Path.Combine(caseFolder, FileName);

    public static List<Ioc> Load(string caseFolder)
    {
        if (string.IsNullOrWhiteSpace(caseFolder)) return new List<Ioc>();
        var p = PathFor(caseFolder);
        return File.Exists(p) ? Parse(File.ReadAllText(p)).Iocs : new List<Ioc>();
    }

    /// <summary>Normalised text: header, then IOCs grouped by kind.</summary>
    public static string Format(IEnumerable<Ioc> iocs, string? caseName = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Case IOCs — one per line, text after \" #\" is a comment.");
        sb.AppendLine("# Prefix user: or file: for user names and bare file names.");
        if (!string.IsNullOrWhiteSpace(caseName)) sb.AppendLine($"# Case: {caseName}");
        foreach (var g in iocs.GroupBy(i => i.Kind).OrderBy(g => Array.IndexOf(KindOrder, g.Key)))
        {
            sb.AppendLine();
            sb.AppendLine($"# {g.Key}");
            foreach (var i in g) sb.AppendLine(i.ToLine());
        }
        return sb.ToString();
    }

    public static void Save(string caseFolder, IEnumerable<Ioc> iocs, string? caseName = null) =>
        File.WriteAllText(PathFor(caseFolder), Format(iocs, caseName), new UTF8Encoding(false));
}

/// <summary>
/// Finds case IOCs in a line of text. Matching is exact on token boundaries:
/// 1.2.3.4 does not hit 11.2.3.45; a CIDR matches every address in it; a
/// domain also matches its subdomains; a file name matches as a whole path
/// component; Amcache's "0000"-padded SHA1 values match.
/// </summary>
public sealed class IocMatcher
{
    private static readonly Regex Ipv4Rx = new(@"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d|\.\d)", RegexOptions.Compiled);
    private static readonly Regex Ipv6Rx = new(@"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])", RegexOptions.Compiled);
    private static readonly Regex HexRx = new(@"(?<![0-9A-Fa-f])(?:0000(?<h>[0-9A-Fa-f]{40})|(?<h>[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32}))(?![0-9A-Fa-f])", RegexOptions.Compiled);
    private static readonly Regex HostRx = new(@"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}(?![A-Za-z0-9-])", RegexOptions.Compiled);

    private readonly Dictionary<string, Ioc> _ips = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(IPAddress Net, int Prefix, Ioc Ioc)> _cidrs = new();
    private readonly Dictionary<string, Ioc> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Ioc> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Ioc> _substrings = new();   // URL, Email
    private readonly List<Ioc> _files = new();
    private readonly Regex? _users;
    private readonly Dictionary<string, Ioc> _userMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool _anyV6;

    public IReadOnlyList<Ioc> Iocs { get; }

    public IocMatcher(IEnumerable<Ioc> iocs)
    {
        Iocs = iocs.ToList();
        foreach (var i in Iocs)
        {
            switch (i.Kind)
            {
                case "IP":
                    _ips[i.Value] = i;
                    if (i.Value.Contains(':')) _anyV6 = true;
                    break;
                case "CIDR":
                    var parts = i.Value.Split('/');
                    if (IPAddress.TryParse(parts[0], out var net) && int.TryParse(parts[1], out var p))
                    {
                        _cidrs.Add((net, p, i));
                        if (net.AddressFamily == AddressFamily.InterNetworkV6) _anyV6 = true;
                    }
                    break;
                case "MD5": case "SHA1": case "SHA256": _hashes[i.Value] = i; break;
                case "Domain": _domains[i.Value] = i; break;
                case "URL": case "Email": _substrings.Add(i); break;
                case "File": _files.Add(i); break;
                case "User": _userMap[i.Value] = i; break;
            }
        }
        if (_userMap.Count > 0)
            _users = new Regex(@"(?<![A-Za-z0-9_.\-])(?:" +
                string.Join("|", _userMap.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape)) +
                @")(?![A-Za-z0-9_\-])", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    }

    public bool IsEmpty => Iocs.Count == 0;

    /// <summary>Distinct IOCs found in one line.</summary>
    public List<Ioc> Match(string line)
    {
        var found = new List<Ioc>();
        if (string.IsNullOrEmpty(line)) return found;
        void Add(Ioc i) { if (!found.Contains(i)) found.Add(i); }

        if (_ips.Count > 0 || _cidrs.Count > 0)
        {
            foreach (Match m in Ipv4Rx.Matches(line)) CheckIp(m.Value, Add);
            if (_anyV6 && (line.Contains("::", StringComparison.Ordinal) || line.Count(c => c == ':') >= 3))
                foreach (Match m in Ipv6Rx.Matches(line))
                    if (m.Value.Count(c => c == ':') >= 2) CheckIp(m.Value, Add);
        }
        if (_hashes.Count > 0)
            foreach (Match m in HexRx.Matches(line))
                if (_hashes.TryGetValue(m.Groups["h"].Value, out var h)) Add(h);
        if (_domains.Count > 0)
            foreach (Match m in HostRx.Matches(line))
            {
                // host and each parent: a.b.evil.com → b.evil.com → evil.com
                var host = m.Value;
                while (true)
                {
                    if (_domains.TryGetValue(host, out var d)) { Add(d); break; }
                    int dot = host.IndexOf('.');
                    if (dot < 0 || host.IndexOf('.', dot + 1) < 0) break;
                    host = host[(dot + 1)..];
                }
            }
        foreach (var s in _substrings)
            if (line.Contains(s.Value, StringComparison.OrdinalIgnoreCase)) Add(s);
        foreach (var f in _files)
            if (ContainsPath(line, f.Value)) Add(f);
        if (_users != null)
            foreach (Match m in _users.Matches(line))
                if (_userMap.TryGetValue(m.Value, out var u)) Add(u);
        return found;
    }

    private void CheckIp(string candidate, Action<Ioc> add)
    {
        if (!IPAddress.TryParse(candidate, out var ip)) return;
        if (_ips.TryGetValue(ip.ToString(), out var hit)) add(hit);
        foreach (var (net, prefix, ioc) in _cidrs)
            if (InNetwork(ip, net, prefix)) add(ioc);
    }

    private static bool InNetwork(IPAddress ip, IPAddress net, int prefix)
    {
        if (ip.AddressFamily != net.AddressFamily) return false;
        var a = ip.GetAddressBytes();
        var b = net.GetAddressBytes();
        int full = prefix / 8, rem = prefix % 8;
        for (int i = 0; i < full; i++) if (a[i] != b[i]) return false;
        if (rem == 0) return true;
        int mask = 0xFF << (8 - rem) & 0xFF;
        return (a[full] & mask) == (b[full] & mask);
    }

    private static bool IsPathChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '-' or '.';

    /// <summary>
    /// Whole-path-component match: "x.sh" hits "/tmp/x.sh" but not "/tmp/ax.sh";
    /// "/tmp/x" does not hit "/tmp/x2". Windows values compare case-insensitively.
    /// </summary>
    private static bool ContainsPath(string line, string value)
    {
        bool windows = value.Contains('\\') || CaseIocs.LooksLikeFile(value) && !value.StartsWith('/');
        var cmp = windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        bool absolute = value.StartsWith('/') || value.Contains(":\\") || value.StartsWith("\\\\") || value.StartsWith('%');
        int idx = 0;
        while ((idx = line.IndexOf(value, idx, cmp)) >= 0)
        {
            char before = idx > 0 ? line[idx - 1] : ' ';
            int endPos = idx + value.Length;
            char after = endPos < line.Length ? line[endPos] : ' ';
            bool okBefore = absolute ? !IsPathChar(before) : before is '/' or '\\' || !IsPathChar(before);
            bool okAfter = !IsPathChar(after) && after is not '/' and not '\\';
            if (okBefore && okAfter) return true;
            idx = endPos;
        }
        return false;
    }
}

/// <summary>One case IOC seen in one collection: how often, when, where.</summary>
public sealed class IocHit
{
    private const int MaxSamples = 3;

    public Ioc Ioc { get; init; } = null!;
    public int Count { get; private set; }
    public DateTime? First { get; private set; }
    public DateTime? Last { get; private set; }
    public SortedSet<string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Samples { get; } = new();

    public void Add(string source, DateTime? ts, string sample)
    {
        Count++;
        Sources.Add(source);
        if (ts.HasValue)
        {
            if (First == null || ts < First) First = ts;
            if (Last == null || ts > Last) Last = ts;
        }
        if (Samples.Count >= MaxSamples) return;
        sample = sample.Replace('\t', ' ').Trim();
        if (sample.Length > 150) sample = sample[..147] + "...";
        var s = $"[{source}{(ts.HasValue ? " " + ts.Value.ToString("yyyy-MM-dd HH:mm:ss") : "")}] {sample}";
        if (!Samples.Contains(s)) Samples.Add(s);
    }
}
