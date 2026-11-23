using System.Diagnostics;
using CsirtTriage.Core.Kape;
using CsirtTriage.Core;
using CsirtTriage.Core.Reporting;

namespace CsirtTriage.Core.Kape;

/// <summary>
/// Runs every enabled analyser over each host's KAPE module output and writes
/// the results folder (default Level2\&lt;host&gt;\…), then the case-wide steps (IOC search, case summary).
/// A host is processed once: delete its results folder (or .processed) to redo it.
/// </summary>
public sealed class AnalysisEngine
{
    public const string ProcessedMarkerFile = ".processed";

    private readonly AnalyserConfig _config;
    private readonly Action<string> _log;

    public AnalysisEngine(AnalyserConfig config, Action<string> log)
    {
        _config = config;
        _log = log;
    }

    public static bool IsProcessed(string outputBase, string collection) =>
        File.Exists(Path.Combine(outputBase, collection, ProcessedMarkerFile));

    /// <summary>
    /// Loads rules.json. Call once before analysing; rules are read on every
    /// run so edits take effect without restarting.
    /// </summary>
    public void LoadRules()
    {
        if (!RuleSet.TryLoad(_config.ResolveRulesPath(), out var rulesMessage))
        {
            _log($"[ERROR] Detection rules not loaded: {rulesMessage}");
            throw new InvalidOperationException("Detection rules not loaded: " + rulesMessage);
        }
        _log($"Rules: {rulesMessage}");
    }

    /// <summary>Every KAPE host in the case, one after another, then the case-wide steps.</summary>
    public void RunAll(CancellationToken ct, IProgress<double>? progress = null)
    {
        LoadRules();
        var outputBase = _config.ResolveOutputPath();
        Directory.CreateDirectory(outputBase);
        _log($"Output: {outputBase}");

        var hosts = KapeDiscovery.FindInCase(_config.CaseFolderPath, outputBase);
        if (hosts.Count == 0)
        {
            _log("[WARN] No KAPE module output found in Processed\\ or the case folder (looked for EZ Tools CSVs such as *_EvtxECmd_Output.csv).");
            return;
        }

        for (int i = 0; i < hosts.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (IsProcessed(outputBase, hosts[i].Name))
                _log($"===== Skipping {hosts[i].Name}: already processed =====");
            else
                AnalyseHost(hosts[i], ct, p => progress?.Report((i + p) / hosts.Count));
            progress?.Report((double)(i + 1) / hosts.Count);
        }

        Case.CaseFinisher.Finish(_config.CaseFolderPath, outputBase, _config.CaseName, _config.AnalystName, _log, ct, _config.SearchIocs);
    }

    /// <summary>
    /// Analyses one KAPE host into Level2\&lt;host folder&gt;. Safe to run for
    /// several hosts at once (one call per host; rules loaded beforehand).
    /// Earlier output for the host is replaced; the .processed marker is
    /// written last, so an interrupted run never looks finished.
    /// </summary>
    public void AnalyseHost(KapeHost host, CancellationToken ct, Action<double>? progress = null)
    {
        var outDir = Path.Combine(_config.ResolveOutputPath(), host.Name);
        if (Directory.Exists(outDir) && Directory.EnumerateFileSystemEntries(outDir).Any())
        {
            _log($"[{host.Name}] Replacing earlier output.");
            Directory.Delete(outDir, recursive: true);
        }
        ProcessHost(host, outDir, ct, progress ?? (_ => { }));
        File.WriteAllText(Path.Combine(outDir, ProcessedMarkerFile), $"Processed {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z{Environment.NewLine}");
    }

    private void ProcessHost(KapeHost host, string outDir, CancellationToken ct, Action<double> progress)
    {
        _log($"===== Host folder: {host.Name} ({host.CsvCount} module CSV file(s)) =====");
        var sw = Stopwatch.StartNew();
        var ctx = new AnalysisContext(_config, host.RootPath, _log, ct);
        var analysers = AnalyserRegistry.CreateAll();

        // Assign each CSV to the first analyser that claims it
        var work = new List<(IArtifactAnalyser A, string File, long Size)>();
        foreach (var file in Directory.EnumerateFiles(host.RootPath, "*.csv",
                     new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
        {
            var name = Path.GetFileName(file);
            var a = analysers.FirstOrDefault(x => x.Accepts(name));
            if (a == null) continue;
            if (!a.Enabled(_config)) continue;
            work.Add((a, file, new FileInfo(file).Length));
        }

        long total = Math.Max(1, work.Sum(w => w.Size)), done = 0;
        foreach (var (a, file, size) in work.OrderBy(w => Array.IndexOf(analysers, w.A)))
        {
            ct.ThrowIfCancellationRequested();
            _log($"[{host.Name}] {a.Source}: {Path.GetRelativePath(host.RootPath, file)} ({size / 1024.0 / 1024.0:N1} MB)");
            try { a.Analyse(file, ctx); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { _log($"[ERROR] [{host.Name}] {a.Source} {Path.GetFileName(file)}: {ex.Message}"); }
            done += size;
            progress((double)done / total);
        }

        var raw = analysers.OfType<IRawFileAnalyser>().Where(a => a.Enabled(_config)).ToArray();
        if (raw.Length > 0) AnalyseRawFiles(host, raw, ctx, ct);

        foreach (var a in analysers.Where(a => a.Enabled(_config)))
        {
            try { a.Complete(ctx); }
            catch (Exception ex) { _log($"[ERROR] [{host.Name}] {a.Source} summary: {ex.Message}"); }
        }

        var hostname = ctx.HostnameVotes.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault()
                       ?? KapeDiscovery.HostFromFolderName(host.Name) ?? host.Name.ToUpperInvariant();
        _log($"[{host.Name}] Hostname: {hostname}" + (ctx.HostIps.Count > 0 ? $"   IP(s): {string.Join(", ", ctx.HostIps)}" : ""));

        var modules = analysers.Select(a => (a.Source, a.Module, a.Enabled(_config))).ToList();
        HostReport.Write(outDir, new Case.CollectionInfo(hostname, host.Name, Case.CollectionKind.Kape, host.RootPath, "", ctx.HostIps.ToList()), ctx, modules,
            _config.CaseName, _config.AnalystName);

        int crit = ctx.Findings.Count(f => f.Severity == Severity.Critical), high = ctx.Findings.Count(f => f.Severity == Severity.High);
        _log($"[{host.Name}] {ctx.Findings.Count} finding(s): {crit} critical, {high} high — {sw.Elapsed:mm\\:ss}. QuickWins: {Path.Combine(outDir, HostReport.QuickWinsFile)}");
        try { QuickWinsRtf.Convert(outDir); }
        catch (Exception ex) { _log($"[WARN] [{host.Name}] RTF conversion failed: {ex.Message} — the text source is still available."); }
    }

    /// <summary>
    /// Raw files (PowerShell history, web server logs) from the host's KAPE
    /// output folder and from its extracted collection in Decompressed\ (a
    /// folder named like the host folder, or a DFIR ORC folder for the same
    /// host). Each folder tree is listed once; a file found in both places
    /// (same name, size and start) is read once.
    /// </summary>
    private void AnalyseRawFiles(KapeHost host, IRawFileAnalyser[] raw, AnalysisContext ctx, CancellationToken ct)
    {
        var outputBase = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_config.ResolveOutputPath())) + Path.DirectorySeparatorChar;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };

        foreach (var root in RawRoots(host, ctx))
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", options); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _log($"[WARN] [{host.Name}] Cannot list {root}: {ex.Message}"); continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                if (file.StartsWith(outputBase, StringComparison.OrdinalIgnoreCase)) continue;
                var a = raw.FirstOrDefault(x => x.AcceptsRaw(file));
                if (a == null || !seen.Add(FileIdentity(file))) continue;
                _log($"[{host.Name}] {a.Source}: {file}");
                try { a.Analyse(file, ctx); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { _log($"[ERROR] [{host.Name}] {a.Source} {Path.GetFileName(file)}: {ex.Message}"); }
            }
        }
    }

    /// <summary>The host's KAPE output folder, plus its folder(s) in Decompressed\.</summary>
    private IEnumerable<string> RawRoots(KapeHost host, AnalysisContext ctx)
    {
        yield return host.RootPath;
        var decompressed = Path.Combine(_config.CaseFolderPath, "Decompressed");
        if (!Directory.Exists(decompressed)) yield break;

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { host.Name };
        if (KapeDiscovery.HostFromFolderName(host.Name) is { } orcHost) names.Add(orcHost);
        if (ctx.HostnameVotes.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault() is { } voted) names.Add(voted);

        string[] dirs;
        try { dirs = Directory.GetDirectories(decompressed); } catch { yield break; }
        var hostRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(host.RootPath)) + Path.DirectorySeparatorChar;
        foreach (var d in dirs.OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            var n = Path.GetFileName(d);
            if (!names.Contains(n) && !(KapeDiscovery.HostFromFolderName(n) is { } h && names.Contains(h))) continue;
            if (hostRoot.StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(d)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue;   // already listed
            yield return d;
        }
    }

    private static string FileIdentity(string path)
    {
        var fi = new FileInfo(path);
        var head = new byte[4096];
        int n = 0;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            n = fs.Read(head, 0, head.Length);
        }
        catch (IOException) { return path; }
        catch (UnauthorizedAccessException) { return path; }
        return $"{fi.Name}|{fi.Length}|{Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(head.AsSpan(0, n)))}";
    }
}
