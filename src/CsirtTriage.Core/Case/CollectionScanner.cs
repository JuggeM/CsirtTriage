using System.Globalization;
using System.Text.RegularExpressions;
using CsirtTriage.Core.Uac;

namespace CsirtTriage.Core.Case;

public enum CollectionStatus
{
    /// <summary>UAC archive in Uploads\, not extracted yet.</summary>
    NotExtracted,
    /// <summary>UAC collection extracted, not analysed yet.</summary>
    Extracted,
    /// <summary>ORC archive or extracted ORC collection without KAPE output in Processed\ yet.</summary>
    WaitingForKape,
    /// <summary>KAPE output in Processed\, not analysed yet.</summary>
    Ready,
    /// <summary>Analysed: Level2\&lt;collection&gt;\.processed exists.</summary>
    Analysed,
}

/// <summary>One collection found in the case folder, as shown in the collections table.</summary>
public sealed record CollectionEntry
{
    /// <summary>Folder name used for Processed\ and Level2\ (unique in the case).</summary>
    public required string Name { get; init; }
    public required string Host { get; init; }
    /// <summary>UAC or KAPE; an ORC collection waiting for KAPE is KAPE.</summary>
    public required CollectionKind Kind { get; init; }
    public required CollectionStatus Status { get; init; }
    /// <summary>UAC: archive in Uploads\ (when there is one).</summary>
    public string? ArchivePath { get; init; }
    /// <summary>UAC: extracted collection root. KAPE: the host's module output folder. Null until it exists.</summary>
    public string? SourcePath { get; init; }
    /// <summary>Archive size (not extracted yet) or size on disk of the source folder; null when not measured.</summary>
    public long? SizeBytes { get; init; }
    /// <summary>Collection date from the archive or folder name, when it has one.</summary>
    public DateTime? Collected { get; init; }
    /// <summary>When the analysis finished (from the .processed marker).</summary>
    public DateTime? AnalysedAt { get; init; }
    /// <summary>Extra information for the table, e.g. why it is waiting.</summary>
    public string Note { get; init; } = "";

    public bool CanRun => Status is CollectionStatus.NotExtracted or CollectionStatus.Extracted
                                 or CollectionStatus.Ready or CollectionStatus.Analysed;
    /// <summary>Pre-selected in the table: everything that can run and isn't analysed yet.</summary>
    public bool SelectedByDefault => Status is CollectionStatus.NotExtracted or CollectionStatus.Extracted or CollectionStatus.Ready;

    public string KindLabel => Kind == CollectionKind.Uac ? "UAC" : "KAPE";
    public string OsLabel => Kind == CollectionKind.Uac ? "Linux/Unix" : "Windows";
    public string StatusLabel => Status switch
    {
        CollectionStatus.NotExtracted => "Not extracted",
        CollectionStatus.Extracted => "Extracted",
        CollectionStatus.WaitingForKape => "Waiting for KAPE",
        CollectionStatus.Ready => "KAPE output ready",
        _ => AnalysedAt.HasValue ? $"Analysed {AnalysedAt.Value.ToLocalTime():yyyy-MM-dd HH:mm}" : "Analysed",
    };
    /// <summary>What running it would do.</summary>
    public string ActionLabel => Status switch
    {
        CollectionStatus.NotExtracted => "Extract + analyse",
        CollectionStatus.Extracted or CollectionStatus.Ready => "Analyse",
        CollectionStatus.Analysed => "Re-analyse",
        _ => "—",
    };
}

/// <summary>
/// Finds every collection in a case folder:
///   Uploads\ (or Upload\)   UAC archives, ORC archives
///   Decompressed\           extracted UAC and ORC collections
///   Processed\              KAPE output (from the ORC processing script) and UAC normalised CSVs
///   Level2\                 analysis results (.processed marker per collection)
/// Only reads the folder; extracting and analysing is <see cref="CaseRunner"/>'s job.
/// </summary>
public static class CollectionScanner
{
    public static readonly string[] UploadFolders = { "Uploads", "Upload" };
    public const string DecompressedFolder = "Decompressed";
    public const string ProcessedFolder = "Processed";
    public const string ResultsFolder = "Level2";

    private static readonly string[] OrcArchiveExtensions = { ".7z", ".zip" };
    private static readonly string[] UacOsNames =
        { "linux", "aix", "freebsd", "macos", "netbsd", "netscaler", "openbsd", "solaris", "esxi", "android" };

    public static List<CollectionEntry> Scan(string caseFolder, string? resultsRoot = null, bool measureSizes = true)
    {
        var list = new List<CollectionEntry>();
        if (!Directory.Exists(caseFolder)) return list;
        resultsRoot ??= Path.Combine(caseFolder, ResultsFolder);
        var decompressed = Path.Combine(caseFolder, DecompressedFolder);
        var uploads = UploadFolders.Select(f => Path.Combine(caseFolder, f)).Where(Directory.Exists).ToList();

        // ── UAC ──────────────────────────────────────────────────────
        var uacFolders = ParserOrchestrator.FindCollections(decompressed);
        var uacNames = new HashSet<string>(uacFolders.Keys, StringComparer.OrdinalIgnoreCase);
        var archives = uploads.SelectMany(u => UacExtractor.ArchivePatterns.SelectMany(p => SafeFiles(u, p)))
            .GroupBy(UacExtractor.CollectionName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        foreach (var name in uacNames.Union(archives.Keys, StringComparer.OrdinalIgnoreCase))
        {
            uacFolders.TryGetValue(name, out var root);
            archives.TryGetValue(name, out var archive);
            var analysedAt = AnalysedAt(resultsRoot, name);
            list.Add(new CollectionEntry
            {
                Name = name,
                Host = UacHost(name),
                Kind = CollectionKind.Uac,
                Status = analysedAt.HasValue ? CollectionStatus.Analysed
                       : root != null ? CollectionStatus.Extracted : CollectionStatus.NotExtracted,
                ArchivePath = archive,
                SourcePath = root,
                SizeBytes = archive != null ? SafeLength(archive) : measureSizes && root != null ? FolderSize(root) : null,
                Collected = DateFromName(name),
                AnalysedAt = analysedAt,
                Note = root == null && archive != null ? Path.GetFileName(archive) : "",
            });
        }

        // ── KAPE (output from the ORC processing script) ─────────────
        var kapeHosts = KapeDiscovery.FindInCase(caseFolder, resultsRoot);
        var kapeHostNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in kapeHosts)
        {
            var host = KapeDiscovery.HostFromFolderName(h.Name) ?? h.Name.ToUpperInvariant();
            kapeHostNames.Add(host);
            var analysedAt = AnalysedAt(resultsRoot, h.Name);
            list.Add(new CollectionEntry
            {
                Name = h.Name,
                Host = host,
                Kind = CollectionKind.Kape,
                Status = analysedAt.HasValue ? CollectionStatus.Analysed : CollectionStatus.Ready,
                SourcePath = h.RootPath,
                SizeBytes = measureSizes ? FolderSize(h.RootPath) : null,
                Collected = DateFromName(h.Name),
                AnalysedAt = analysedAt,
                Note = $"{h.CsvCount} module CSV file(s)",
            });
        }

        // ── ORC collections the processing script hasn't handled yet ──
        // Extracted ORC folders (not UAC) and ORC archives whose host has no KAPE output.
        var waiting = new Dictionary<string, (string Name, string Path, bool Archive)>(StringComparer.OrdinalIgnoreCase);
        if (Directory.Exists(decompressed))
            foreach (var dir in SafeDirs(decompressed))
            {
                var name = Path.GetFileName(dir);
                // UAC folders (also empty ones from an interrupted extraction) are not ORC
                if (uacNames.Contains(name) || archives.ContainsKey(name) || name.StartsWith("uac", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith('_') || name.StartsWith('.')) continue;
                var host = KapeDiscovery.HostFromFolderName(name) ?? name.ToUpperInvariant();
                if (!kapeHostNames.Contains(host)) waiting.TryAdd(host, (name, dir, false));
            }
        foreach (var u in uploads)
            foreach (var file in SafeFiles(u, "*").Where(f => OrcArchiveExtensions.Contains(Path.GetExtension(f).ToLowerInvariant())))
            {
                var name = Path.GetFileNameWithoutExtension(file);
                var host = KapeDiscovery.HostFromFolderName(name);
                if (host == null || kapeHostNames.Contains(host)) continue;
                waiting.TryAdd(host, (name, file, true));
            }
        foreach (var (host, w) in waiting)
            list.Add(new CollectionEntry
            {
                Name = w.Name,
                Host = host,
                Kind = CollectionKind.Kape,
                Status = CollectionStatus.WaitingForKape,
                SourcePath = null,
                SizeBytes = w.Archive ? SafeLength(w.Path) : null,
                Collected = DateFromName(w.Name),
                Note = w.Archive ? $"{Path.GetFileName(w.Path)}: run the ORC processing script first"
                                 : "no KAPE output in Processed\\ yet: run the ORC processing script first",
            });

        return list.OrderBy(e => e.Host, StringComparer.OrdinalIgnoreCase)
                   .ThenBy(e => e.Collected ?? DateTime.MaxValue)
                   .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                   .ToList();
    }

    /// <summary>Host from a UAC collection name: uac-&lt;host&gt;-&lt;os&gt;-&lt;timestamp&gt;.</summary>
    public static string UacHost(string name)
    {
        var m = Regex.Match(name, @"^uac-(?<h>.+?)-(?<os>" + string.Join("|", UacOsNames) + @")-\d{8}", RegexOptions.IgnoreCase);
        if (m.Success) return m.Groups["h"].Value;
        m = Regex.Match(name, @"^uac-(?<h>[^-]+)", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups["h"].Value : name;
    }

    /// <summary>yyyyMMdd (optionally followed by hhmmss or _hhmmss) anywhere in the name.</summary>
    public static DateTime? DateFromName(string name)
    {
        var m = Regex.Match(name, @"(?<!\d)(?<d>20\d{6})(?:[_T-]?(?<t>\d{6}))?(?!\d)");
        if (!m.Success) return null;
        var s = m.Groups["d"].Value + (m.Groups["t"].Success ? m.Groups["t"].Value : "000000");
        return DateTime.TryParseExact(s, "yyyyMMddHHmmss", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;
    }

    private static DateTime? AnalysedAt(string resultsRoot, string name)
    {
        var marker = Path.Combine(resultsRoot, name, ParserOrchestrator.ProcessedMarkerFile);
        try { return File.Exists(marker) ? File.GetLastWriteTimeUtc(marker) : null; }
        catch { return null; }
    }

    public static long? FolderSize(string dir)
    {
        try
        {
            return Directory.EnumerateFiles(dir, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
                .Sum(f => SafeLength(f) ?? 0);
        }
        catch { return null; }
    }

    private static long? SafeLength(string file)
    {
        try { return new FileInfo(file).Length; } catch { return null; }
    }

    private static IEnumerable<string> SafeFiles(string dir, string pattern)
    {
        try { return Directory.GetFiles(dir, pattern); } catch { return Array.Empty<string>(); }
    }

    private static IEnumerable<string> SafeDirs(string dir)
    {
        try { return Directory.GetDirectories(dir); } catch { return Array.Empty<string>(); }
    }
}
