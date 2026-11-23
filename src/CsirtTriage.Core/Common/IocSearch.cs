using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace CsirtTriage.Core;

/// <summary>
/// Searches one collection's data for the case IOCs. Each collection type has
/// its own sources, but the result (one <see cref="IocHit"/> per IOC seen) and
/// the output written from it are the same for every collection.
/// </summary>
public static class IocSearch
{
    private const long MaxRawFileBytes = 50L * 1024 * 1024;
    private static readonly Regex TimeRx = new(@"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", RegexOptions.Compiled);

    // UAC sources whose rows only carry the file's write time, not an event time
    private static readonly HashSet<string> UntimedSources = new(StringComparer.OrdinalIgnoreCase)
    {
        "CRONTAB", "BASH", "ZSH", "SH", "PYHISTORY", "LESSHST", "VIMINFO", "WGETHSTS", "DBHISTORY", "MYSQL", "PSQL",
    };

    private static List<IocHit> Ordered(Dictionary<Ioc, IocHit> hits) =>
        hits.Values.OrderBy(h => Array.IndexOf(CaseIocs.KindOrder, h.Ioc.Kind)).ThenByDescending(h => h.Count).ToList();

    // ── KAPE ─────────────────────────────────────────────────────────
    /// <summary>
    /// Every EZ Tools CSV of a KAPE host, raw lines, so columns no analyser
    /// reads are covered too.
    /// </summary>
    public static List<IocHit> SearchKapeHost(string kapeRoot, IocMatcher matcher, CancellationToken ct = default)
    {
        var hits = new Dictionary<Ioc, IocHit>();
        if (matcher.IsEmpty || !Directory.Exists(kapeRoot)) return new();

        var files = Directory.EnumerateFiles(kapeRoot, "*.csv", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
            .Where(f => KapeDiscovery.IsKnownCsv(Path.GetFileName(f)));
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var source = KapeSource(Path.GetFileName(file));
            long n = 0;
            foreach (var line in SafeLines(file))
            {
                if ((++n & 0x3FFF) == 0) ct.ThrowIfCancellationRequested();
                var found = matcher.Match(line);
                if (found.Count == 0) continue;
                var tm = TimeRx.Match(line);
                DateTime? ts = tm.Success ? CsvReader.ParseTime(tm.Groups[1].Value) : null;
                foreach (var ioc in found)
                {
                    if (!hits.TryGetValue(ioc, out var h)) hits[ioc] = h = new IocHit { Ioc = ioc };
                    h.Add(source, ts, line);
                }
            }
        }
        return Ordered(hits);
    }

    private static string KapeSource(string file)
    {
        foreach (var a in Kape.AnalyserRegistry.CreateAll())
            if (a.Accepts(file)) return a.Source;
        return "CSV";
    }

    // ── M365 ─────────────────────────────────────────────────────────
    /// <summary>
    /// A Microsoft 365 collection: Normalized_UAL.csv in Processed\&lt;collection&gt;,
    /// which holds every record with its full AuditData (client IPs, user
    /// agents, rule parameters, forwarding addresses, file names).
    /// </summary>
    public static List<IocHit> SearchM365(string processedDir, IocMatcher matcher, CancellationToken ct = default)
    {
        var hits = new Dictionary<Ioc, IocHit>();
        var file = Path.Combine(processedDir, M365.M365Engine.NormalizedFile);
        if (matcher.IsEmpty || !File.Exists(file)) return new();
        bool header = true;
        long n = 0;
        foreach (var line in SafeLines(file))
        {
            if (header) { header = false; continue; }
            if ((++n & 0x3FFF) == 0) ct.ThrowIfCancellationRequested();
            var found = matcher.Match(line);
            if (found.Count == 0) continue;
            var f = SplitCsv(line);
            DateTime? ts = f.Count > 0 ? M365.UalRecord.ParseTime(f[0]) : null;
            var source = f.Count > 3 && f[3].Length > 0
                ? "M365-" + (f[3].Equals("AzureActiveDirectory", StringComparison.OrdinalIgnoreCase) ? "ENTRA" : f[3].ToUpperInvariant())
                : "M365";
            var sample = f.Count > 6 ? $"{(f.Count > 4 ? f[4] + ": " : "")}{f[6]}" : line;
            foreach (var ioc in found)
            {
                if (!hits.TryGetValue(ioc, out var h)) hits[ioc] = h = new IocHit { Ioc = ioc };
                h.Add(source, ts, sample);
            }
        }
        return Ordered(hits);
    }

    // ── UAC ──────────────────────────────────────────────────────────
    /// <summary>
    /// A UAC collection: its normalised CSVs (Processed\&lt;collection&gt;), the
    /// scored body file (Level2\&lt;collection&gt;) and the raw live response
    /// output under the extracted collection.
    /// </summary>
    public static List<IocHit> SearchUacCollection(string processedDir, string resultsDir, string? rawRoot,
                                                   IocMatcher matcher, CancellationToken ct = default)
    {
        var hits = new Dictionary<Ioc, IocHit>();
        if (matcher.IsEmpty) return new();
        void Record(Ioc ioc, string source, DateTime? ts, string sample)
        {
            if (!hits.TryGetValue(ioc, out var h)) hits[ioc] = h = new IocHit { Ioc = ioc };
            h.Add(source, ts, sample);
        }

        // Normalized_*.csv: Timestamp,Hostname,LogType,Daemon,User,IP,Message,Severity,Raw
        if (Directory.Exists(processedDir))
            foreach (var csv in Directory.EnumerateFiles(processedDir, "Normalized_*.csv"))
            {
                ct.ThrowIfCancellationRequested();
                var fallbackSource = Path.GetFileNameWithoutExtension(csv)["Normalized_".Length..];
                bool header = true;
                string? firstTs = null;
                bool oneTimestamp = true;
                var fileHits = new List<(Ioc Ioc, string Src, DateTime? Ts, string Msg)>();
                foreach (var line in SafeLines(csv))
                {
                    if (header) { header = false; continue; }
                    int comma = line.IndexOf(',');
                    var rawTs = comma > 0 ? line[..comma] : "";
                    if (firstTs == null) firstTs = rawTs;
                    else if (oneTimestamp && rawTs != firstTs) oneTimestamp = false;

                    var m = matcher.Match(line);
                    if (m.Count == 0) continue;
                    var f = SplitCsv(line);
                    DateTime? ts = f.Count > 0 && DateTime.TryParse(f[0], CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;
                    var src = f.Count > 2 && !string.IsNullOrWhiteSpace(f[2]) ? f[2] : fallbackSource;
                    var msg = f.Count > 6 && !string.IsNullOrWhiteSpace(f[6]) ? f[6] : line;
                    foreach (var ioc in m) fileHits.Add((ioc, src, ts, msg));
                }
                // History files and crontabs carry no event time: every row gets the
                // file's write time, which would make "last seen" look like today.
                bool untimed = fileHits.Count > 0 &&
                    (fileHits[0].Src.Equals("CRONTAB", StringComparison.OrdinalIgnoreCase)
                     || oneTimestamp && UntimedSources.Contains(fileHits[0].Src));
                foreach (var h in fileHits) Record(h.Ioc, h.Src, untimed ? null : h.Ts, h.Msg);
            }

        // Body file: Path,Size,Mode,UID,GID,MD5,AccessTimeUtc,ModTimeUtc,ChangeTimeUtc,BirthTimeUtc
        var body = Path.Combine(resultsDir, "ProcessedBodyFile.csv");
        if (File.Exists(body))
        {
            bool header = true;
            foreach (var line in SafeLines(body))
            {
                if (header) { header = false; continue; }
                var m = matcher.Match(line);
                if (m.Count == 0) continue;
                var f = SplitCsv(line);
                DateTime? ts = f.Count > 7 && DateTime.TryParse(f[7].Replace(" UTC", ""), CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;
                var sample = f.Count > 5 ? $"{f[0]} (mode {f[2]}, uid {f[3]}{(f[5].Length > 0 ? ", md5 " + f[5] : "")}, mtime)" : line;
                foreach (var ioc in m) Record(ioc, "BODYFILE", ts, sample);
            }
        }

        // hash_executables.sha1 ("<sha1>  <path>"): a case SHA1 or path seen on disk
        if (rawRoot != null && Directory.Exists(rawRoot))
        {
            string? hashFile = null;
            try { hashFile = Directory.EnumerateFiles(rawRoot, "hash_executables.sha1", SearchOption.AllDirectories).FirstOrDefault(); }
            catch { /* unreadable folder */ }
            if (hashFile != null)
                foreach (var line in SafeLines(hashFile))
                    foreach (var ioc in matcher.Match(line))
                        Record(ioc, "HASHES", null, line.Trim());
        }

        // Raw live response output
        if (rawRoot != null && Directory.Exists(rawRoot))
        {
            List<string> lrDirs;
            try { lrDirs = Directory.EnumerateDirectories(rawRoot, "live_response", SearchOption.AllDirectories).ToList(); }
            catch { lrDirs = new(); }
            foreach (var lr in lrDirs)
            {
                List<string> files;
                try { files = Directory.EnumerateFiles(lr, "*", SearchOption.AllDirectories).ToList(); }
                catch { continue; }
                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    try { if (new FileInfo(file).Length > MaxRawFileBytes) continue; } catch { continue; }
                    var rel = Path.GetRelativePath(lr, file).Replace('\\', '/');
                    foreach (var line in SafeLines(file))
                        foreach (var ioc in matcher.Match(line))
                            Record(ioc, "LIVE_RESPONSE", null, $"{rel}: {line.Trim()}");
                }
            }
        }
        return Ordered(hits);
    }

    // ── Helpers ──────────────────────────────────────────────────────
    /// <summary>Lines of a file; stops quietly when the file can't be read (locked, deleted, bad encoding).</summary>
    public static IEnumerable<string> SafeLines(string path)
    {
        IEnumerator<string>? e = null;
        try { e = File.ReadLines(path).GetEnumerator(); }
        catch { yield break; }
        using (e)
        {
            while (true)
            {
                string line;
                try { if (!e.MoveNext()) yield break; line = e.Current; }
                catch { yield break; }
                yield return line;
            }
        }
    }

    public static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else sb.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        fields.Add(sb.ToString());
        return fields;
    }
}
