using System.Text;
using CsirtTriage.Core.Reporting;

namespace CsirtTriage.Core.Case;

/// <summary>
/// Case-wide steps over every analysed collection in Level2\ (UAC and KAPE
/// alike). They only read analysed output, so they also run on their own
/// ("Search IOCs" in the IOC panel) without re-analysing anything:
/// case IOC search per collection, CaseSummary.txt / CaseFindings.csv,
/// CaseTracker.xlsx and iocs_discovered.txt.
/// </summary>
public static class CaseFinisher
{
    public sealed record Result(int IocCount, int CollectionsSearched, int CollectionsWithHits, int IocsHit);

    public static Result Finish(string caseFolder, string resultsRoot, string caseName, string analyst,
                                Action<string> log, CancellationToken ct = default, bool searchIocs = true)
    {
        var result = new Result(0, 0, 0, 0);
        if (!Directory.Exists(resultsRoot)) return result;
        if (searchIocs) result = SearchIocs(caseFolder, resultsRoot, log, ct);

        string? summary = null;
        try
        {
            summary = CaseSummary.Write(resultsRoot, caseName, analyst);
            if (summary != null) log($"Case summary written: {summary}");
        }
        catch (Exception ex) { log($"[WARN] Case summary failed: {ex.Message}"); }

        if (summary != null)
        {
            var tracker = Path.Combine(resultsRoot, CaseTracker.FileName);
            try
            {
                // Every critical and high finding as case tracker rows; the Case report panel exports the ticked ones
                var data = CaseReport.Build(resultsRoot, caseName, analyst);
                var rows = CaseTracker.Rows(data, data.Findings.Where(f => f.Rank <= 1));
                CaseTracker.Write(tracker, rows);
                log($"Case tracker rows ({rows.Count} critical/high) written: {tracker}");
            }
            catch (IOException ex) { log($"[WARN] {CaseTracker.FileName} not written — is it open in Excel? {ex.Message}"); }
            catch (Exception ex) { log($"[WARN] {CaseTracker.FileName} not written: {ex.Message}"); }
        }

        try
        {
            int n = WriteDiscovered(caseFolder, resultsRoot);
            if (n > 0) log($"{n} discovered IOC(s) not yet in the case IOC list: {Path.Combine(resultsRoot, CaseIocs.DiscoveredFileName)}");
        }
        catch (Exception ex) { log($"[WARN] Discovered IOC list failed: {ex.Message}"); }
        return result;
    }

    /// <summary>Analysed collections: every folder in Level2\ with a host.txt.</summary>
    public static List<(string Dir, CollectionInfo Info)> Collections(string resultsRoot) =>
        !Directory.Exists(resultsRoot) ? new()
        : Directory.GetDirectories(resultsRoot)
            .Select(d => (Dir: d, Info: CollectionInfo.Read(d)))
            .Where(x => x.Info != null)
            .Select(x => (x.Dir, x.Info!))
            .OrderBy(x => x.Item1, StringComparer.OrdinalIgnoreCase)
            .ToList();

    // ── Case IOC search ──────────────────────────────────────────────
    public static Result SearchIocs(string caseFolder, string resultsRoot, Action<string> log, CancellationToken ct = default)
    {
        var iocs = CaseIocs.Load(caseFolder);
        var matcher = new IocMatcher(iocs);
        int searched = 0, withHits = 0;
        var hitValues = new HashSet<Ioc>();
        if (iocs.Count > 0) log($"IOC search: {iocs.Count} case IOC(s) across analysed collections…");

        foreach (var (dir, info) in Collections(resultsRoot))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                List<IocHit> hits = new();
                if (iocs.Count > 0)
                {
                    if (info.Kind == CollectionKind.Kape && !Directory.Exists(info.SourceRoot))
                    {
                        log($"[WARN] {info.Collection}: KAPE output folder no longer exists ({info.SourceRoot}) — IOC search skipped.");
                        continue;
                    }
                    hits = info.Kind switch
                    {
                        CollectionKind.Kape => IocSearch.SearchKapeHost(info.SourceRoot, matcher, ct),
                        CollectionKind.M365 => IocSearch.SearchM365(info.ProcessedDir, matcher, ct),
                        _ => IocSearch.SearchUacCollection(info.ProcessedDir, dir, Directory.Exists(info.SourceRoot) ? info.SourceRoot : null, matcher, ct),
                    };
                    searched++;
                    if (hits.Count > 0) withHits++;
                    foreach (var h in hits) hitValues.Add(h.Ioc);
                    log(hits.Count > 0
                        ? $"[WARN] {info.Collection}: {hits.Count} of {iocs.Count} case IOC(s) seen — {string.Join(", ", hits.Take(5).Select(h => h.Ioc.Value))}{(hits.Count > 5 ? ", …" : "")}"
                        : $"{info.Collection}: no case IOC hits.");
                }
                HostReport.WriteIocHits(dir, info.Hostname, hits, iocs);
                RenderQuickWins(dir, info);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { log($"[WARN] {info.Collection}: IOC search failed: {ex.Message}"); }
        }
        if (iocs.Count > 0)
            log($"IOC search: {hitValues.Count} of {iocs.Count} case IOC(s) seen, on {withHits} of {searched} collection(s).");
        return new Result(iocs.Count, searched, withHits, hitValues.Count);
    }

    /// <summary>QuickWins.rtf from the collection's text source, in its own layout.</summary>
    public static void RenderQuickWins(string resultsDir, CollectionInfo info)
    {
        if (info.Kind is CollectionKind.Kape or CollectionKind.M365) QuickWinsRtf.Convert(resultsDir);
        else Uac.QuickWinsRtfConverter.Convert(resultsDir);
    }

    // ── Discovered IOCs (pivot loop) ─────────────────────────────────
    /// <summary>
    /// Writes Level2\iocs_discovered.txt: indicators the analysis pulled out of
    /// findings across all collections that are not in iocs.txt yet and are not
    /// a case host's own address. Same format as iocs.txt, so the analyst can
    /// copy lines over (or use "Load discovered" in the IOC panel).
    /// </summary>
    public static int WriteDiscovered(string caseFolder, string resultsRoot)
    {
        var caseList = CaseIocs.Load(caseFolder);
        var known = new HashSet<string>(caseList.Select(i => i.Value), StringComparer.OrdinalIgnoreCase);
        var covered = new IocMatcher(caseList);   // e.g. an IP inside a listed CIDR, a path ending in a listed file
        var ownIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var found = new Dictionary<(string Kind, string Value), (SortedSet<string> Hosts, SortedSet<string> Sources)>();

        foreach (var (dir, info) in Collections(resultsRoot))
        {
            ownIps.UnionWith(info.Ips);
            var rows = ReadFindings(Path.Combine(dir, HostReport.FindingsFile))
                .Select(r => (Source: r.Source, Finding: r.Detail.Length > 0 ? $"{r.Text} {r.Detail}" : r.Text));
            foreach (var kv in Uac.KeyFindingsBuilder.ExtractIocs(rows))
            {
                if (!found.TryGetValue(kv.Key, out var e))
                    found[kv.Key] = e = (new SortedSet<string>(StringComparer.OrdinalIgnoreCase), new SortedSet<string>());
                e.Hosts.Add(info.Hostname);
                e.Sources.UnionWith(kv.Value);
            }
        }

        var list = found
            .Where(kv => !known.Contains(kv.Key.Value) && covered.Match(kv.Key.Value).Count == 0)
            .Where(kv => !(kv.Key.Kind == "IP" && ownIps.Contains(kv.Key.Value)))
            .OrderByDescending(kv => kv.Value.Hosts.Count)
            .ThenByDescending(kv => kv.Value.Sources.Count)
            .ThenBy(kv => Uac.KeyFindingsBuilder.IocKindOrder(kv.Key.Kind))
            .ThenBy(kv => kv.Key.Value, StringComparer.Ordinal)
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("# IOCs found in the findings of this case that are NOT yet in the case IOC list (<case>\\iocs.txt).");
        sb.AppendLine("# Review, then copy the lines you trust into iocs.txt (or use \"Load discovered\" in the IOC panel)");
        sb.AppendLine("# and search again — that finds every other place the indicator shows up.");
        sb.AppendLine($"# Generated {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();
        foreach (var kv in list)
        {
            var value = kv.Key.Kind switch
            {
                "Account" => "user:" + kv.Key.Value,
                "File" when !CaseIocs.LooksLikeFile(kv.Key.Value) => "file:" + kv.Key.Value,
                _ => kv.Key.Value,
            };
            sb.AppendLine($"{value,-45}  # discovered: {kv.Value.Hosts.Count} host(s) {string.Join(",", kv.Value.Hosts)}; sources {string.Join(",", kv.Value.Sources)}");
        }
        File.WriteAllText(Path.Combine(resultsRoot, CaseIocs.DiscoveredFileName), sb.ToString(), new UTF8Encoding(false));
        return list.Count;
    }

    private sealed record FindingRow(string Source, string Text, string Detail);

    // TimeUtc,LastUtc,Host,Severity,Source,Category,Count,Text,Detail,Artifact
    private static IEnumerable<FindingRow> ReadFindings(string path)
    {
        bool header = true;
        foreach (var line in IocSearch.SafeLines(path))
        {
            if (header) { header = false; continue; }
            var f = IocSearch.SplitCsv(line);
            if (f.Count >= 9) yield return new FindingRow(f[4], f[7], f[8]);
        }
    }
}
