using System;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

using CsirtTriage.Core.Uac;
using CsirtTriage.Core.Uac.Output;
using CsirtTriage.Core.Uac.Parsers.Docker;
using CsirtTriage.Core.Uac.Output;
using CsirtTriage.Core.Uac.Parsers;
using CsirtTriage.Core.Uac;

namespace CsirtTriage.Core.Uac;

/// <summary>
/// Replaces Form1's parser orchestration entirely.
/// Driven by ParserConfig — all parser toggles, thresholds and
/// keyword lists come from the analyst's UI settings.
/// </summary>
public class ParserOrchestrator
{
    private readonly ParserConfig _config;
    private readonly Action<string> _log;   // posts a message to the UI log

    // Host UTC offset for the collection currently being processed, resolved
    // once at the top of ProcessLogs() and pushed onto every LogFileParser
    // instance created for that collection. One orchestrator handles one
    // collection at a time; run collections in parallel with one instance each.
    private TimeSpan? _currentHostUtcOffset;
    private string _currentHostname = string.Empty;

    // Every finding for the collection being processed, tagged with its source,
    // so the KEY FINDINGS / IOC block can be built once all parsers have run.
    private readonly List<(string Source, string Finding)> _collectedFindings = new();
    private readonly List<CoverageTable.SourceInfo> _sourceInfos = new();
    private readonly Dictionary<string, Dictionary<string, int>> _patternsBySource = new();
    // Processed\<collection>: the normalised CSVs (parsed data, level 1).
    // Everything else for the collection goes to Level2\<collection>.
    private string _processedDir = string.Empty;

    public ParserOrchestrator(ParserConfig config, Action<string> log)
    {
        _config = config;
        _log = log;
    }

    // ── Public entry points ──────────────────────────────────────────
    /// <summary>Every UAC collection in Decompressed\, one after another, then the case-wide steps.</summary>
    public void RunAll(CancellationToken ct = default, IProgress<double>? progress = null)
    {
        var outputBase = _config.ResolveOutputPath();
        _log($"Output: {outputBase}");
        Directory.CreateDirectory(outputBase);

        var collections = FindCollections(Path.Combine(_config.CaseFolderPath, "Decompressed")).ToList();
        if (collections.Count == 0)
            _log("[WARN] No UAC collections found under Decompressed\\.");

        for (int i = 0; i < collections.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var (collectionName, rootPath) = collections[i];
            if (IsCollectionProcessed(outputBase, collectionName))
                _log($"===== Skipping {collectionName}: already processed =====");
            else
                AnalyseCollection(collectionName, rootPath, ct);
            progress?.Report((double)(i + 1) / collections.Count);
        }

        Case.CaseFinisher.Finish(_config.CaseFolderPath, outputBase, _config.CaseName, _config.AnalystName, _log, ct);
    }

    /// <summary>
    /// Parses and analyses one extracted UAC collection: normalised CSVs to
    /// Processed\&lt;collection&gt;, analysis results to Level2\&lt;collection&gt;.
    /// Earlier output for the collection is replaced (several writers append,
    /// so processing on top of it would duplicate rows). The .processed
    /// marker is written last, so an interrupted run never looks finished.
    /// </summary>
    public void AnalyseCollection(string collectionName, string rootPath, CancellationToken ct = default)
    {
        var outputDir = Path.Combine(_config.ResolveOutputPath(), collectionName);
        _processedDir = Path.Combine(_config.CaseFolderPath, "Processed", collectionName);
        foreach (var dir in new[] { outputDir, _processedDir })
            if (Directory.Exists(dir) && Directory.EnumerateFileSystemEntries(dir).Any())
            {
                _log($"[{collectionName}] Replacing earlier output in {dir}");
                Directory.Delete(dir, recursive: true);
            }
        Directory.CreateDirectory(outputDir);
        Directory.CreateDirectory(_processedDir);

        _log($"===== Collection: {collectionName} =====");
        _collectedFindings.Clear();
        _sourceInfos.Clear();
        _patternsBySource.Clear();
        _currentHostname = string.Empty;
        _currentHostUtcOffset = null;

        if (_config.ParseAuth || _config.ParseCrontab || _config.ParseMessages
            || _config.ParseSyslog || _config.ParseWebLogs || _config.ParseDocker
            || _config.ParseAudit || _config.ParseLiveResponse || _config.ParseJournal)
        {
            ct.ThrowIfCancellationRequested();
            ProcessLogs(collectionName, rootPath, outputDir);
        }

        if (_config.ParseBodyFile)
        {
            ct.ThrowIfCancellationRequested();
            ProcessBodyFile(collectionName, rootPath, outputDir);
        }

        if (_config.ParseHashes)
        {
            ct.ThrowIfCancellationRequested();
            ProcessHashes(collectionName, rootPath, outputDir);
        }

        // Analyst summary at the top of QuickWins — built last so it covers
        // every source, including the body file. Also writes Findings.csv and
        // host.txt, which the case-wide steps read.
        ct.ThrowIfCancellationRequested();
        WriteKeyFindings(collectionName, rootPath, outputDir);
        _log($"===== Done: {collectionName} =====");

        try
        {
            QuickWinsRtfConverter.Convert(outputDir);
            _log($"[{collectionName}] QuickWins.rtf written.");
        }
        catch (Exception ex)
        {
            _log($"[WARN] [{collectionName}] RTF conversion failed: {ex.Message}");
        }

        File.WriteAllText(Path.Combine(outputDir, ProcessedMarkerFile),
            $"Processed {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z{Environment.NewLine}");
    }

    // ── Processed-state check ────────────────────────────────────────
    /// <summary>Marker written to Level2\&lt;collection&gt;\ once all parsing is done.</summary>
    public const string ProcessedMarkerFile = ".processed";

    /// <summary>
    /// True when the collection has been fully processed and saved under
    /// <paramref name="outputBase"/>. Delete the collection's output folder
    /// (or just the marker) to force it to be processed again.
    /// </summary>
    public static bool IsCollectionProcessed(string outputBase, string collectionName) =>
        !string.IsNullOrWhiteSpace(outputBase)
        && File.Exists(Path.Combine(outputBase, collectionName, ProcessedMarkerFile));

    // ── Collection discovery ─────────────────────────────────────────
    /// <summary>Extracted UAC collections in Decompressed\: name → collection root.</summary>
    public static Dictionary<string, string> FindCollections(string decompressDir)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!Directory.Exists(decompressDir)) return map;

        foreach (var folder in Directory.GetDirectories(decompressDir)
                     .Where(f => Path.GetFileName(f).StartsWith("uac", StringComparison.OrdinalIgnoreCase)))
        {
            var collectionName = Path.GetFileName(folder);

            // An empty folder is a failed/interrupted extraction, not a
            // collection — processing it would mark it ".processed" with no data.
            if (!Directory.EnumerateFileSystemEntries(folder).Any())
                continue;

            // UAC archives often contain a nested folder with the same name
            var nested = Path.Combine(folder, collectionName);
            var rootPath = Directory.Exists(nested) ? nested : folder;
            map[collectionName] = rootPath;
        }

        return map;
    }

    // ── Log parsing ──────────────────────────────────────────────────
    private void ProcessLogs(string collectionName, string rootPath, string outputDir)
    {
        _log($"[{collectionName}] Starting log parsing…");

        // Prefer the host's own view of its name (live_response / etc/hostname);
        // the collection folder name is only a fallback.
        string hostname = HostnameResolver.Resolve(rootPath);
        if (!string.IsNullOrEmpty(hostname))
            _log($"[{collectionName}] Hostname resolved from UAC artifacts: {hostname}");
        else
        {
            hostname = ExtractHostnameFromCollection(collectionName);
            _log($"[{collectionName}] No hostname artifact found — using collection name: {hostname}");
        }
        _currentHostname = hostname;

        // Resolved once per collection from UAC's timedatectl/date artifacts.
        // Null means no timezone artifact was found — timestamps are left
        // uncorrected rather than silently assumed UTC.
        _currentHostUtcOffset = HostTimezoneResolver.Resolve(rootPath);
        if (_currentHostUtcOffset.HasValue)
            _log($"[{collectionName}] Host UTC offset resolved: {_currentHostUtcOffset.Value:hh\\:mm} " +
                 $"(applying to all log timestamps)");
        else
            _log($"[{collectionName}] No timezone artifact found — timestamps left uncorrected");

        QuickWinsHeader.EnsureHeader(outputDir, DateTime.UtcNow, null, null);

        var suspiciousLogs = new Dictionary<string, List<string>>();
        var patternCounts = new Dictionary<string, Dictionary<string, int>>();
        var firstLastSeen = new Dictionary<string, (DateTime, DateTime)>();
        var ipLogs = new Dictionary<string, Dictionary<string, int>>();
        var fileCounts = new Dictionary<string, int>();
        var perFileTimestamps = new Dictionary<string, Dictionary<string, (DateTime, DateTime)>>();
        var sessionTracker = new SessionTracker();

        void Parse(string baseName, LogFileParser parser, string label)
        {
            var csvPath = Path.Combine(_processedDir, $"Normalized_{label}.csv");
            using var csv = CreateCsv(csvPath, append: false);
            TryAttach(parser, sessionTracker);
            TryAttach(parser, csv);
            TryAttach(parser, hostname);
            parser.SetHostUtcOffset(_currentHostUtcOffset);
            ParseLogFiles(parser, rootPath, baseName, outputDir,
                suspiciousLogs, patternCounts, firstLastSeen,
                ipLogs, fileCounts, perFileTimestamps);
        }

        if (_config.ParseAuth)
            ParseAuthLogs(rootPath, outputDir, sessionTracker, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseAudit)
            ParseGrouped("audit.log", new AuditLogParser(), "AUDIT",
                rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseMessages)
            ParseGrouped("messages", new MessagesLogParser(), "MESSAGES",
                rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseSyslog)
            ParseGrouped("syslog", new SyslogParser(), "SYSLOG",
                rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        // Cron runtime logs now handled by SyslogParser (Debian/Ubuntu) above.
        // CrontabScanner scans actual job definition files for persistence.
        if (_config.ParseCrontab)
            ParseCrontabFiles(rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseWebLogs)
        {
            using var webCsv = CreateCsv(
                Path.Combine(_processedDir, "Normalized_WEB.csv"), append: false);
            var webParser = new WebLogParser();
            var webBfd = new WebBruteForceDetector();  // shared across all web files
            TryAttach(webParser, webCsv);
            TryAttach(webParser, hostname);
            webParser.SetHostUtcOffset(_currentHostUtcOffset);
            webParser.AttachBruteForceDetector(webBfd);
            ParseWebLogs(webParser, webBfd, rootPath, outputDir,
                suspiciousLogs, patternCounts, firstLastSeen,
                ipLogs, fileCounts, perFileTimestamps);
        }

        if (_config.ParseDocker)
        {
            var dockerPath = Directory.EnumerateDirectories(
                rootPath, "containers", SearchOption.AllDirectories).FirstOrDefault();

            if (!string.IsNullOrEmpty(dockerPath) && Directory.Exists(dockerPath))
            {
                _log($"[{collectionName}] Parsing Docker containers…");
                using var dockerCsv = CreateCsv(
                    Path.Combine(_processedDir, "Normalized_DOCKER.csv"), append: false);
                var dockerParser = new DockerParserCoordinator(dockerPath);
                TryAttach(dockerParser, dockerCsv);
                TryAttach(dockerParser, hostname);
                dockerParser.SetHostUtcOffset(_currentHostUtcOffset);

                var (findings, patterns, first, last) = dockerParser.ProcessLogAndWriteQuickWins();
                suspiciousLogs["DOCKER"] = findings;
                patternCounts["DOCKER"] = patterns;
                firstLastSeen["DOCKER"] = (first, last);
                ipLogs["DOCKER"] = new Dictionary<string, int>();
                fileCounts["DOCKER"] = 1;
                perFileTimestamps["DOCKER"] = new Dictionary<string, (DateTime, DateTime)>
                    { { "docker", (first, last) } };

                // Docker findings previously never reached QuickWins.txt — this
                // method only returned them (ProcessLogAndReturnFindings doesn't
                // write). They aren't per-file like the other log types, so they
                // go in under a single "containers" group.
                if (findings.Count > 0)
                {
                    var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
                    QuickWinsSectionWriter.WriteSection(
                        quickWinsFile, "DOCKER", "No suspicious container configuration detected.",
                        new List<(string FileName, List<string> Findings)> { ("containers", findings) });
                }
            }
            else
            {
                _log($"[{collectionName}] Docker: containers folder not found — skipping.");
            }
        }

        // Live response log artefacts
        if (_config.ParseLiveResponse)
        {
            var lrPath = Directory.EnumerateDirectories(
                rootPath, "live_response", SearchOption.AllDirectories).FirstOrDefault();

            if (!string.IsNullOrEmpty(lrPath) && Directory.Exists(lrPath))
            {
                try
                {
                    // Running processes / open connections → findings
                    var lrDetailed = LiveResponseTriage.AnalyzeDetailed(lrPath, _currentHostUtcOffset);
                    var lrFindings = lrDetailed.Select(d => d.Finding).ToList();
                    suspiciousLogs["LIVE_RESPONSE"] = lrFindings;
                    patternCounts["LIVE_RESPONSE"] = lrDetailed
                        .GroupBy(d => d.Pattern)
                        .ToDictionary(g => g.Key, g => g.Count());
                    // Only wtmp/btmp findings carry a time; the rest describe the collection moment
                    var lrTimes = lrFindings
                        .Select(f => Regex.Match(f, @"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\]"))
                        .Where(m => m.Success)
                        .Select(m => DateTime.ParseExact(m.Groups[1].Value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))
                        .ToList();
                    firstLastSeen["LIVE_RESPONSE"] = lrTimes.Count > 0
                        ? (lrTimes.Min(), lrTimes.Max())
                        : (DateTime.MaxValue, DateTime.MinValue);
                    ipLogs["LIVE_RESPONSE"] = new Dictionary<string, int>();
                    fileCounts["LIVE_RESPONSE"] = 1;
                    if (lrFindings.Count > 0)
                    {
                        _log($"[{collectionName}] LiveResponse: {lrFindings.Count} finding(s).");
                        QuickWinsSectionWriter.WriteSection(
                            Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile), "LIVE_RESPONSE",
                            "No live response findings.",
                            new List<(string FileName, List<string> Findings)> { ("live_response", lrFindings) });
                    }
                }
                catch (Exception ex)
                {
                    _log($"[ERROR] LiveResponse: {ex.Message}");
                }
            }
            else
            {
                _log($"[{collectionName}] LiveResponse: folder not found — skipping.");
            }
        }

        // systemd journal files: system + user, active, archived (@) and dirty (~)
        if (_config.ParseJournal)
        {
            var journalFiles = DiscoverJournalFiles(rootPath);

            if (journalFiles.Count > 0)
            {
                _log($"[{collectionName}] Parsing {journalFiles.Count} journal file(s)…");

                const string logKey = "JOURNAL";
                var allFindings = new List<string>();
                var perFileFindings = new List<(string FileName, List<string> Findings)>();
                var combinedPatterns = new Dictionary<string, int>();
                DateTime jFirst = DateTime.MaxValue, jLast = DateTime.MinValue;

                var csvPath = Path.Combine(_processedDir, "Normalized_JOURNAL.csv");
                using var csv = CreateCsv(csvPath, append: false);
                var journalParser = new JournalFileParser();
                TryAttach(journalParser, csv);
                TryAttach(journalParser, hostname);
                journalParser.SetHostUtcOffset(_currentHostUtcOffset);

                perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

                foreach (var jFile in journalFiles)
                {
                    _log($"Parsing {Path.GetFileName(jFile)}");

                    // ParseFile returns findings WITHOUT writing to QuickWins,
                    // so we can write ONE combined section below.
                    var (findings, patterns, first, last) = journalParser.ParseFile(jFile);

                    // Relative path as key: system.journal can exist in both
                    // /var/log/journal/<id>/ and /run/log/journal/<id>/
                    perFileTimestamps[logKey][Path.GetRelativePath(rootPath, jFile)] = (first, last);

                    if (findings.Count > 0)
                        perFileFindings.Add((jFile, findings));

                    allFindings.AddRange(findings);

                    foreach (var kv in patterns)
                        combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                            ? ex + kv.Value : kv.Value;

                    if (first != DateTime.MaxValue && first < jFirst) jFirst = first;
                    if (last != DateTime.MinValue && last > jLast) jLast = last;
                }

                // Write ONE combined section with per-file subheaders
                if (perFileFindings.Count > 0)
                {
                    var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
                    QuickWinsSectionWriter.WriteSection(
                        quickWinsFile, "JOURNAL", "No suspicious activity detected.",
                        perFileFindings);
                }

                suspiciousLogs[logKey] = allFindings;
                patternCounts[logKey] = combinedPatterns;
                firstLastSeen[logKey] = (jFirst, jLast);
                ipLogs[logKey] = new Dictionary<string, int>();
                fileCounts[logKey] = journalFiles.Count;
            }
            else
            {
                _log($"[{collectionName}] Journal: no *.journal files found — skipping.");
            }
        }

        // CRON findings written by ParseGrouped above

        // ── Bash history ─────────────────────────────────────────────
        if (_config.ParseBashHistory)
        {
            var histFiles = Parsers.BashHistoryParser.DiscoverHistoryFiles(rootPath);

            if (histFiles.Count > 0)
            {
                _log($"[{collectionName}] Parsing {histFiles.Count} bash_history file(s)…");

                const string logKey = "BASH";
                var allFindings = new List<string>();
                var perFileFindings = new List<(string File, List<string> Findings)>();
                var combinedPatterns = new Dictionary<string, int>();
                DateTime bashFirst = DateTime.MaxValue, bashLast = DateTime.MinValue;

                using var bashCsv = CreateCsv(
                    Path.Combine(_processedDir, "Normalized_BASH.csv"), append: false);

                var bashParser = new Parsers.BashHistoryParser();
                bashParser.AttachNormalizedWriter(bashCsv);
                bashParser.AttachHostname(hostname);

                perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

                foreach (var (filePath, username) in histFiles)
                {
                    _log($"Parsing bash_history: {username}");
                    var (findings, patterns, first, last) = bashParser.ParseFile(filePath, username);

                    perFileTimestamps[logKey][username] = (first, last);

                    if (findings.Count > 0)
                        perFileFindings.Add((filePath, findings));

                    allFindings.AddRange(findings);

                    foreach (var kv in patterns)
                        combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                            ? ex + kv.Value : kv.Value;

                    if (first != DateTime.MaxValue && first < bashFirst) bashFirst = first;
                    if (last != DateTime.MinValue && last > bashLast) bashLast = last;
                }

                // Write ONE combined QuickWins section with per-user subheaders
                if (perFileFindings.Count > 0)
                {
                    var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
                    QuickWinsSectionWriter.WriteSection(
                        quickWinsFile, "BASH", "No suspicious activity detected.",
                        perFileFindings.Select(pf => (FileName: pf.File, pf.Findings)).ToList());
                }

                suspiciousLogs[logKey] = allFindings;
                patternCounts[logKey] = combinedPatterns;
                firstLastSeen[logKey] = (bashFirst, bashLast);
                ipLogs[logKey] = new Dictionary<string, int>();
                fileCounts[logKey] = histFiles.Count;
            }
            else
            {
                _log($"[{collectionName}] Bash: no bash_history files found — skipping.");
            }
        }

        // ── Zsh history ──────────────────────────────────────────────
        if (_config.ParseZsh)
        {
            using var zshCsv = CreateCsv(Path.Combine(_processedDir, "Normalized_ZSH.csv"), append: false);
            var zshParser = new Parsers.ZshHistoryParser();
            zshParser.AttachNormalizedWriter(zshCsv);
            zshParser.AttachHostname(hostname);
            RunUserHistoryBlock("ZSH", collectionName, outputDir, hostname,
                Parsers.ZshHistoryParser.DiscoverFiles(rootPath),
                (p, u) => zshParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── VimInfo ───────────────────────────────────────────────────
        if (_config.ParseVimInfo)
        {
            using var vimCsv = CreateCsv(Path.Combine(_processedDir, "Normalized_VIMINFO.csv"), append: false);
            var vimParser = new Parsers.VimInfoParser();
            vimParser.AttachNormalizedWriter(vimCsv);
            vimParser.AttachHostname(hostname);
            RunUserHistoryBlock("VIMINFO", collectionName, outputDir, hostname,
                Parsers.VimInfoParser.DiscoverFiles(rootPath),
                (p, u) => vimParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Database history ──────────────────────────────────────────
        if (_config.ParseDbHistory)
        {
            using var dbCsv = CreateCsv(Path.Combine(_processedDir, "Normalized_DBHISTORY.csv"), append: false);
            var dbParser = new Parsers.DbHistoryParser();
            dbParser.AttachNormalizedWriter(dbCsv);
            dbParser.AttachHostname(hostname);
            RunUserHistoryBlock("DBHISTORY", collectionName, outputDir, hostname,
                Parsers.DbHistoryParser.DiscoverFiles(rootPath),
                (p, u) => dbParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Python history ────────────────────────────────────────────
        if (_config.ParsePythonHistory)
        {
            using var pyCsv = CreateCsv(Path.Combine(_processedDir, "Normalized_PYHISTORY.csv"), append: false);
            var pyParser = new Parsers.PythonHistoryParser();
            pyParser.AttachNormalizedWriter(pyCsv);
            pyParser.AttachHostname(hostname);
            RunUserHistoryBlock("PYHISTORY", collectionName, outputDir, hostname,
                Parsers.PythonHistoryParser.DiscoverFiles(rootPath),
                (p, u) => pyParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Wget HSTS ─────────────────────────────────────────────────
        if (_config.ParseWgetHsts)
        {
            using var wgetCsv = CreateCsv(Path.Combine(_processedDir, "Normalized_WGETHSTS.csv"), append: false);
            var wgetParser = new Parsers.WgetHstsParser();
            wgetParser.AttachNormalizedWriter(wgetCsv);
            wgetParser.AttachHostname(hostname);
            RunUserHistoryBlock("WGETHSTS", collectionName, outputDir, hostname,
                Parsers.WgetHstsParser.DiscoverFiles(rootPath),
                (p, u) => wgetParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Less history ──────────────────────────────────────────────
        if (_config.ParseLessHst)
        {
            using var lessCsv = CreateCsv(Path.Combine(_processedDir, "Normalized_LESSHST.csv"), append: false);
            var lessParser = new Parsers.LessHstParser();
            lessParser.AttachNormalizedWriter(lessCsv);
            lessParser.AttachHostname(hostname);
            RunUserHistoryBlock("LESSHST", collectionName, outputDir, hostname,
                Parsers.LessHstParser.DiscoverFiles(rootPath),
                (p, u) => lessParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── AI coding agents (UAC 3.4.0+ ai_tools artifacts) ─────────
        if (_config.ParseAiAgents)
        {
            using var aiCsv = CreateCsv(Path.Combine(_processedDir, $"Normalized_{Parsers.AiAgentParser.LogKey}.csv"), append: false);
            var aiParser = new Parsers.AiAgentParser();
            aiParser.AttachNormalizedWriter(aiCsv);
            aiParser.AttachHostname(hostname);
            RunUserHistoryBlock(Parsers.AiAgentParser.LogKey, collectionName, outputDir, hostname,
                Parsers.AiAgentParser.DiscoverFiles(rootPath),
                (p, u) => aiParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // Finalise QuickWins
        DateTime? overallFirst = null, overallLast = null;
        // CRONTAB "times" are file modification times (often the extraction
        // time), not log entries — they would stretch the coverage to "now".
        foreach (var fl in firstLastSeen.Where(kv => kv.Key != "CRONTAB").Select(kv => kv.Value))
        {
            // Exclude both sentinels: firstSeen starts at MaxValue, lastSeen at MinValue
            if (fl.Item1 != DateTime.MinValue && fl.Item1 != DateTime.MaxValue)
                overallFirst = overallFirst == null ? fl.Item1
                    : fl.Item1 < overallFirst ? fl.Item1 : overallFirst;
            if (fl.Item2 != DateTime.MinValue && fl.Item2 != DateTime.MaxValue)
                overallLast = overallLast == null ? fl.Item2
                    : fl.Item2 > overallLast ? fl.Item2 : overallLast;
        }

        QuickWinsHeader.UpsertTimeline(outputDir, overallFirst, overallLast);

        // The old [GLOBAL] Summary (findings again) and per-log summaries
        // (patterns again) are replaced by the COVERAGE table and one
        // PATTERN COUNTS block, written in WriteKeyFindings once all sources ran.
        foreach (var kv in fileCounts)
        {
            firstLastSeen.TryGetValue(kv.Key, out var fl);
            _sourceInfos.Add(new CoverageTable.SourceInfo(kv.Key, kv.Value, fl.Item1, fl.Item2,
                TimesAreFileMtimes: kv.Key == "CRONTAB"));
        }
        foreach (var kv in patternCounts)
            if (kv.Value != null && kv.Value.Count > 0) _patternsBySource[kv.Key] = kv.Value;

        if (_config.OutputCollapseDups)
        {
            QuickWinsTidy.GroupSuspiciousFindingsUniform(outputDir);
            QuickWinsTidy.CollapseVerboseSessions(outputDir, 5);
            // CollapseCronDuplicates removed — grouping done at parse time
            QuickWinsTidy.CollapseSyslogDuplicates(outputDir, 2);
            QuickWinsTidy.CollapseMessagesDuplicates(outputDir, 2);
        }

        foreach (var kv in suspiciousLogs)
            foreach (var f in kv.Value)
                _collectedFindings.Add((kv.Key, f));

        _log($"[{collectionName}] QuickWins written.");
    }

    // Sources the analyst asked for — shown as "not found" in COVERAGE when absent
    private IEnumerable<string> ExpectedSources()
    {
        if (_config.ParseAuth) yield return "AUTH.LOG";
        if (_config.ParseAudit) yield return "AUDIT";
        if (_config.ParseSyslog) yield return "SYSLOG";
        if (_config.ParseMessages) yield return "MESSAGES";
        if (_config.ParseCrontab) yield return "CRONTAB";
        if (_config.ParseJournal) yield return "JOURNAL";
        if (_config.ParseLiveResponse) yield return "LIVE_RESPONSE";
        if (_config.ParseBodyFile) yield return "BODYFILE";
        if (_config.ParseHashes) yield return "HASHES";
        if (_config.ParseBashHistory) yield return "BASH";
        if (_config.ParseWebLogs) yield return "WEB";
        if (_config.ParseDocker) yield return "DOCKER";
    }

    // ── Key findings / IOC block ─────────────────────────────────────
    private void WriteKeyFindings(string collectionName, string rootPath, string outputDir)
    {
        var host = string.IsNullOrEmpty(_currentHostname)
            ? ExtractHostnameFromCollection(collectionName) : _currentHostname;

        var hostIps = HostIpResolver.Resolve(rootPath);
        _log(hostIps.Count > 0
            ? $"[{collectionName}] Host IP(s): {string.Join(", ", hostIps)}"
            : $"[{collectionName}] Host IP: not found in live_response");

        QuickWinsHeader.EnsureHeader(outputDir, DateTime.UtcNow, null, null);

        // InsertGlobalAfterTimeline puts each block directly under the
        // timeline, so insert bottom-up: coverage, IOCs, key findings, context.
        QuickWinsHeader.InsertGlobalAfterTimeline(outputDir, "COVERAGE (what was checked)",
            CoverageTable.Build(_sourceInfos, ExpectedSources(), _collectedFindings));
        QuickWinsHeader.InsertGlobalAfterTimeline(outputDir, "IOCs (indicators seen in findings)",
            KeyFindingsBuilder.BuildIocs(_collectedFindings, hostIps.Select(i => i.Address)));
        QuickWinsHeader.InsertGlobalAfterTimeline(outputDir, "KEY FINDINGS (critical/high, all sources)",
            KeyFindingsBuilder.BuildKeyFindings(_collectedFindings));
        QuickWinsHeader.InsertGlobalAfterTimeline(outputDir, "HOST",
            KeyFindingsBuilder.BuildContext(host, collectionName, _currentHostUtcOffset,
                _config.CaseName, _config.AnalystName, hostIps));

        // Pattern counts once, at the end
        var pc = new System.Text.StringBuilder();
        pc.AppendLine();
        pc.AppendLine("########## PATTERN COUNTS (all sources) ##########");
        foreach (var l in CoverageTable.BuildPatternCounts(_patternsBySource)) pc.AppendLine(l);
        File.AppendAllText(Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile), pc.ToString(),
            new System.Text.UTF8Encoding(false));

        // Machine-readable findings and collection info for the case-wide steps
        // (same files as a KAPE collection writes)
        Reporting.HostReport.WriteFindingsCsv(Path.Combine(outputDir, Reporting.HostReport.FindingsFile), host,
            UacFindings.FromAll(_collectedFindings));
        new Case.CollectionInfo(host, collectionName, Case.CollectionKind.Uac, rootPath, _processedDir,
            hostIps.Select(i => i.Address).ToList()).Write(outputDir);

        _log($"[{collectionName}] Key findings: " +
             $"{_collectedFindings.Count(f => KeyFindingsBuilder.Parse(f.Source, f.Finding).Rank <= 1)} critical/high.");
    }

    // ── Crontab definition file scanner ─────────────────────────────
    private void ParseCrontabFiles(
        string rootPath,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        const string logKey = "CRONTAB";

        var crontabFiles = CrontabScanner.DiscoverCrontabFiles(rootPath);
        fileCounts[logKey] = crontabFiles.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (crontabFiles.Count == 0)
        {
            _log("CRONTAB: no crontab definition files found.");
            return;
        }

        _log($"CRONTAB: scanning {crontabFiles.Count} crontab file(s)…");

        var csvPath = Path.Combine(_processedDir, "Normalized_CRONTAB.csv");
        using var csv = CreateCsv(csvPath, append: false);
        var scanner = new CrontabScanner();
        TryAttach(scanner, csv);
        scanner.SetHostUtcOffset(_currentHostUtcOffset);

        var allFindings = new List<string>();
        var perFileFindings = new List<(string FilePath, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        DateTime combFirst = DateTime.MaxValue;
        DateTime combLast = DateTime.MinValue;

        foreach (var file in crontabFiles)
        {
            var (findings, patterns, first, last) = scanner.ParseFile(file);

            perFileTimestamps[logKey][Path.GetFileName(file)] = (first, last);

            if (findings.Count > 0)
                perFileFindings.Add((file, findings));

            allFindings.AddRange(findings);

            foreach (var kv in patterns)
                combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                    ? ex + kv.Value : kv.Value;

            if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
            if (last != DateTime.MinValue && last > combLast) combLast = last;
        }

        // Write section
        var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
        QuickWinsSectionWriter.WriteSection(
            quickWinsFile, "CRONTAB", "No suspicious crontab entries found.",
            perFileFindings.Select(pf => (FileName: pf.FilePath, pf.Findings)).ToList());

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (combFirst, combLast);
        ipLogs[logKey] = new Dictionary<string, int>();
    }

    // ── Generic grouped log handler ──────────────────────────────────
    // Calls ParseFile() on each discovered log file and writes ONE combined
    // section header with per-file subheaders. Requires the parser to expose
    // a ParseFile(string) method returning (Findings, Patterns, First, Last).
    private void ParseGrouped(
        string baseName,
        LogFileParser parser,
        string logKey,
        string rootPath,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        var logFiles = Directory.EnumerateFiles(rootPath, baseName + "*",
                SearchOption.AllDirectories)
            .Where(f =>
                f.EndsWith(baseName, StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".1", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(f, $@"{Regex.Escape(baseName)}\.\d+(\.gz)?$",
                    RegexOptions.IgnoreCase))
            .OrderBy(f => f)
            .ToList();

        fileCounts[logKey] = logFiles.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (logFiles.Count == 0) return;

        parser.SetHostUtcOffset(_currentHostUtcOffset);

        // Attach CSV writer if supported
        var csvPath = Path.Combine(_processedDir, $"Normalized_{logKey}.csv");
        using var csv = CreateCsv(csvPath, append: false);
        TryAttach(parser, csv);

        var allFindings = new List<string>();
        var perFileFindings = new List<(string LogFile, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime combFirst = DateTime.MaxValue;
        DateTime combLast = DateTime.MinValue;

        // Use reflection to call ParseFile if available, otherwise fall back to
        // ProcessLogAndWriteQuickWins so existing parsers without ParseFile still work.
        var parseFileMethod = parser.GetType().GetMethod("ParseFile",
            new[] { typeof(string) });

        foreach (var logFile in logFiles)
        {
            string parsePath = logFile;
            string? tempPath = null;

            if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                tempPath = Path.Combine(Path.GetTempPath(),
                    Path.GetFileNameWithoutExtension(logFile) + "_" + Guid.NewGuid().ToString("N"));
                using var inFs = File.OpenRead(logFile);
                using var outFs = File.Create(tempPath);
                using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                gz.CopyTo(outFs);
                parsePath = tempPath;
            }

            _log($"Parsing {Path.GetFileName(parsePath)}");

            List<string> findings;
            Dictionary<string, int> patterns;
            DateTime first, last;

            if (parseFileMethod != null)
            {
                // Value tuple element names (Findings/Patterns/First/Last) are
                // compile-time only — at runtime via reflection use Item1..Item4.
                var result = parseFileMethod.Invoke(parser, new object[] { parsePath })!;
                var resultTuple = (System.Runtime.CompilerServices.ITuple)result;
                findings = (List<string>)resultTuple[0];
                patterns = (Dictionary<string, int>)resultTuple[1];
                first = (DateTime)resultTuple[2];
                last = (DateTime)resultTuple[3];
            }
            else
            {
                (findings, patterns, first, last) =
                    parser.ProcessLogAndWriteQuickWins(parsePath, outputDir, combinedIPs);
            }

            perFileTimestamps[logKey][Path.GetFileName(logFile)] = (first, last);

            if (findings.Count > 0)
                perFileFindings.Add((logFile, findings));

            allFindings.AddRange(findings);

            foreach (var kv in patterns)
                combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                    ? ex + kv.Value : kv.Value;

            if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
            if (last != DateTime.MinValue && last > combLast) combLast = last;

            if (tempPath != null && File.Exists(tempPath))
                File.Delete(tempPath);
        }

        // Write ONE combined section with per-file subheaders
        if (perFileFindings.Count > 0)
        {
            var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
            QuickWinsSectionWriter.WriteSection(
                quickWinsFile, logKey, "No suspicious activity detected.",
                perFileFindings.Select(pf => (FileName: pf.LogFile, pf.Findings)).ToList());
        }

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (combFirst, combLast);
        ipLogs[logKey] = combinedIPs;
    }

    // ── Auth / Secure log handler (grouped — ONE section header) ────────
    private void ParseAuthLogs(
        string rootPath,
        string outputDir,
        SessionTracker sessionTracker,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        // auth.log + auth.log.1 + auth.log.2.gz  AND  secure + secure.1 etc.
        var baseNames = new[] { "auth.log", "secure" };

        foreach (var baseName in baseNames)
        {
            string logKey = baseName.ToUpperInvariant();

            var logFiles = Directory.EnumerateFiles(rootPath, baseName + "*",
                    SearchOption.AllDirectories)
                .Where(f =>
                    f.EndsWith(baseName, StringComparison.OrdinalIgnoreCase) ||
                    f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ||
                    f.EndsWith(".1", StringComparison.OrdinalIgnoreCase) ||
                    Regex.IsMatch(f, $@"{Regex.Escape(baseName)}\.\d+(\.gz)?$",
                        RegexOptions.IgnoreCase))
                .OrderBy(f => f)
                .ToList();

            fileCounts[logKey] = logFiles.Count;
            perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

            if (logFiles.Count == 0) continue;

            var csvPath = Path.Combine(_processedDir, $"Normalized_{logKey.Replace(".", "_")}.csv");
            using var csv = CreateCsv(csvPath, append: false);
            var parser = new AuthSecureLogParser();
            TryAttach(parser, sessionTracker);
            TryAttach(parser, csv);
            parser.SetHostUtcOffset(_currentHostUtcOffset);

            var allFindings = new List<string>();
            var perFileFindings = new List<(string FilePath, List<string> Findings)>();
            var combinedPatterns = new Dictionary<string, int>();
            var combinedIPs = new Dictionary<string, int>();
            DateTime combFirst = DateTime.MaxValue;
            DateTime combLast = DateTime.MinValue;

            foreach (var logFile in logFiles)
            {
                string parsePath = logFile;
                string? tempPath = null;

                if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                {
                    tempPath = Path.Combine(Path.GetTempPath(),
                        Path.GetFileNameWithoutExtension(logFile) + "_" + Guid.NewGuid().ToString("N"));
                    using var inFs = File.OpenRead(logFile);
                    using var outFs = File.Create(tempPath);
                    using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                    gz.CopyTo(outFs);
                    parsePath = tempPath;
                }

                _log($"Parsing {Path.GetFileName(parsePath)}");

                var (findings, patterns, first, last) = parser.ParseFile(parsePath);

                perFileTimestamps[logKey][Path.GetFileName(logFile)] = (first, last);

                if (findings.Count > 0)
                    perFileFindings.Add((logFile, findings)); // logFile = original path, not temp

                allFindings.AddRange(findings);

                foreach (var kv in patterns)
                    combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                        ? ex + kv.Value : kv.Value;

                if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
                if (last != DateTime.MinValue && last > combLast) combLast = last;

                if (tempPath != null && File.Exists(tempPath))
                    File.Delete(tempPath);
            }

            // Write ONE combined section with per-file subheaders
            if (perFileFindings.Count > 0)
            {
                var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
                QuickWinsSectionWriter.WriteSection(
                    quickWinsFile, logKey, "No suspicious activity detected.",
                    perFileFindings.Select(pf => (FileName: pf.FilePath, pf.Findings)).ToList());
            }

            suspiciousLogs[logKey] = allFindings;
            patternCounts[logKey] = combinedPatterns;
            firstLastSeen[logKey] = (combFirst, combLast);
            ipLogs[logKey] = combinedIPs;
        }

        // ── Session output ────────────────────────────────────────────────
        var stats = sessionTracker.GetStatistics();

        // 1. Suspicious sessions → RTF (actionable: root SSH, odd hours, service account SSH etc.)
        var suspiciousLines = sessionTracker.GenerateSuspiciousSummary("AUTH");
        if (suspiciousLines?.Count > 0)
        {
            var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
            using var w = new StreamWriter(quickWinsFile, append: true);
            w.WriteLine();
            w.WriteLine("########## [AUTH] Suspicious Sessions ##########");
            // Stats one-liner so analyst knows the full scale
            w.WriteLine($"  Sessions: {stats.GetValueOrDefault("Total Sessions")} total" +
                        $" | SSH interactive: {stats.GetValueOrDefault("SSH Interactive")}" +
                        $" | Unique IPs: {stats.GetValueOrDefault("Unique IPs")}" +
                        $" | Suspicious: {stats.GetValueOrDefault("Suspicious Sessions")}" +
                        $"  (full detail → Sessions.csv, Sessions_Full.csv)");
            w.WriteLine();
            foreach (var line in suspiciousLines)
                w.WriteLine($"  {line}");
        }

        // 2. Sessions_Full.csv: every individual session, all types (sudo, cron, su, SSH, …)
        var allSessions = sessionTracker.GetAllSessions();
        try { new SessionsCsvWriter(outputDir).WriteAll(allSessions); }
        catch (Exception ex) { _log($"[WARN] [AUTH] Failed to write Sessions_Full.csv: {ex.Message}"); }

        // 3. Sessions.csv and Logons.csv in the shared layout (same columns as
        //    KAPE collections), so the case summary sees SSH logons between
        //    case hosts as lateral movement, across Linux and Windows.
        try
        {
            var ssh = allSessions.Where(x => x.Type == SessionType.SshInteractive).ToList();
            var host = string.IsNullOrEmpty(_currentHostname) ? ExtractHostnameFromCollection(Path.GetFileName(outputDir)) : _currentHostname;
            Reporting.HostReport.WriteSessionsCsv(Path.Combine(outputDir, Reporting.HostReport.SessionsFile), host,
                ssh.Select(x => new CsirtTriage.Core.LogonSession
                {
                    User = x.Username ?? "", LogonType = "SSH", SourceIp = x.SourceIP ?? "", Via = x.Daemon ?? "sshd",
                    Start = x.StartTime, End = x.EndTime, EndedBy = x.EndTime.HasValue ? "session closed" : "",
                }));
            Reporting.HostReport.WriteLogonsCsv(Path.Combine(outputDir, Reporting.HostReport.LogonsFile), host,
                ssh.Where(x => !string.IsNullOrEmpty(x.SourceIP))
                   .GroupBy(x => (User: x.Username ?? "", Ip: x.SourceIP))
                   .Select(g => new CsirtTriage.Core.LogonRecord
                   {
                       User = g.Key.User, LogonType = "SSH", SourceIp = g.Key.Ip, Via = "sshd",
                       Count = g.Count(), First = g.Min(x => x.StartTime), Last = g.Max(x => x.StartTime),
                   }));
        }
        catch (Exception ex)
        {
            _log($"[WARN] Could not write Sessions.csv / Logons.csv: {ex.Message}");
        }
    }

    // ── Generic log file handler (mirrors Form1.ParseLogWithHandler) ──
    private void ParseLogFiles(
        LogFileParser parser,
        string searchRoot,
        string baseFileName,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        var logFiles = Directory.EnumerateFiles(searchRoot, baseFileName + "*",
                SearchOption.AllDirectories)
            .Where(f =>
                f.EndsWith(baseFileName, StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".1", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(f, $@"{Regex.Escape(baseFileName)}\.\d+(\.gz)?$",
                    RegexOptions.IgnoreCase))
            .OrderBy(f => f)
            .ToList();

        string logKey = baseFileName.ToUpperInvariant();
        fileCounts[logKey] = logFiles.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (logFiles.Count == 0) return;

        var allFindings = new List<string>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime combinedFirst = DateTime.MaxValue;
        DateTime combinedLast = DateTime.MinValue;

        foreach (var logFile in logFiles)
        {
            string parsePath = logFile;
            string? tempPath = null;

            if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                tempPath = Path.Combine(Path.GetTempPath(),
                    Path.GetFileNameWithoutExtension(logFile) + "_" + Guid.NewGuid().ToString("N"));

                using var inFs = File.OpenRead(logFile);
                using var outFs = File.Create(tempPath);
                using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                gz.CopyTo(outFs);
                parsePath = tempPath;
            }

            _log($"Parsing {Path.GetFileName(parsePath)}");

            var (findings, patterns, first, last) =
                parser.ProcessLogAndWriteQuickWins(parsePath, outputDir, combinedIPs);

            perFileTimestamps[logKey][Path.GetFileName(logFile)] = (first, last);
            allFindings.AddRange(findings);

            foreach (var kvp in patterns)
                combinedPatterns[kvp.Key] = combinedPatterns.TryGetValue(kvp.Key, out var existing)
                    ? existing + kvp.Value : kvp.Value;

            if (first < combinedFirst) combinedFirst = first;
            if (last > combinedLast) combinedLast = last;

            if (tempPath != null && File.Exists(tempPath))
                File.Delete(tempPath);
        }

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (combinedFirst, combinedLast);
        ipLogs[logKey] = new Dictionary<string, int>(combinedIPs);
    }

    // ── Web log handler (discovery-based) ────────────────────────────
    private void ParseWebLogs(
        WebLogParser parser,
        WebBruteForceDetector bfd,
        string rootPath,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        const string logKey = "WEB";

        var allCandidates = WebLogParser.DiscoverWebLogFiles(rootPath);
        var webLogs = allCandidates
            .Where(p => Path.GetFileName(p).IndexOf("access",
                            StringComparison.OrdinalIgnoreCase) >= 0
                        || WebLogParser.IsErrorLogName(p))
            .OrderBy(p => WebLogParser.IsErrorLogName(p))   // access logs first
            .ThenBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();

        fileCounts[logKey] = webLogs.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (webLogs.Count == 0)
        {
            _log("WEB: no access or error logs discovered.");
            return;
        }

        var allFindings = new List<string>();
        var perFileFindings = new List<(string LogFile, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime first = DateTime.MaxValue, last = DateTime.MinValue;

        foreach (var logFile in webLogs)
        {
            string parsePath = logFile;
            string? tempPath = null;

            if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                tempPath = Path.Combine(Path.GetTempPath(),
                    Path.GetFileNameWithoutExtension(logFile) + "_" +
                    Guid.NewGuid().ToString("N"));
                using var inFs = File.OpenRead(logFile);
                using var outFs = File.Create(tempPath);
                using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                gz.CopyTo(outFs);
                parsePath = tempPath;
            }

            _log($"Parsing WEB {Path.GetRelativePath(rootPath, logFile)}");

            // A decompressed .gz is parsed from a temp path; keep apache2/nginx as daemon
            var lf = logFile.ToLowerInvariant();
            parser.DaemonOverride = tempPath == null ? null
                : lf.Contains("nginx") ? "nginx"
                : lf.Contains("apache") || lf.Contains("httpd") ? "apache2" : "web";
            parser.IsErrorLog = WebLogParser.IsErrorLogName(logFile);

            // Label = path below /var/log (or /var/www), e.g. "apache2/access.log"
            // vs "nginx/access.log" — the bare file name was ambiguous.
            var label = WebLogLabel(rootPath, logFile);

            var (findings, patterns, fileFirst, fileLast) = parser.ParseFile(parsePath);

            perFileTimestamps[logKey][label] = (fileFirst, fileLast);

            if (findings.Count > 0)
                perFileFindings.Add((label, findings));

            allFindings.AddRange(findings);

            foreach (var kvp in patterns)
                combinedPatterns[kvp.Key] = combinedPatterns.TryGetValue(kvp.Key, out var ex)
                    ? ex + kvp.Value : kvp.Value;

            if (fileFirst != DateTime.MaxValue && fileFirst < first) first = fileFirst;
            if (fileLast != DateTime.MinValue && fileLast > last) last = fileLast;

            if (tempPath != null && File.Exists(tempPath))
                File.Delete(tempPath);
        }

        parser.DaemonOverride = null;
        parser.IsErrorLog = null;

        // Brute-force findings from the shared detector (covers all files combined);
        // they come back as finished "[WEB] [SEVERITY] [time] …" lines.
        var bruteList = bfd.GetFindings();
        allFindings.AddRange(bruteList);
        foreach (var bf in bruteList)
        {
            var label = bf.Contains("succeeded") ? "Web brute force succeeded" : "Web brute force";
            combinedPatterns[label] = combinedPatterns.TryGetValue(label, out var n) ? n + 1 : 1;
        }

        // Write ONE combined section — always write if any files were parsed,
        // even if no attack findings, so the RTF always has a WEB section.
        var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
        var webSections = perFileFindings
            .Select(pf => (FileName: pf.LogFile, pf.Findings))
            .ToList();
        if (bruteList.Count > 0)
            webSections.Add(("Brute-force (all files)", bruteList));

        QuickWinsSectionWriter.WriteSection(
            quickWinsFile, "WEB", "No suspicious web requests detected.", webSections);

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (first, last);
        ipLogs[logKey] = new Dictionary<string, int>(combinedIPs);
    }

    private static string WebLogLabel(string rootPath, string logFile)
    {
        var rel = Path.GetRelativePath(rootPath, logFile).Replace('\\', '/');
        foreach (var anchor in new[] { "var/log/", "var/www/" })
        {
            int i = rel.IndexOf(anchor, StringComparison.OrdinalIgnoreCase);
            if (i >= 0) return rel.Substring(i + anchor.Length);
        }
        return Path.GetFileName(logFile);
    }

    // ── Body file ────────────────────────────────────────────────────
    private void ProcessBodyFile(string collectionName, string rootPath, string outputDir)
    {
        var bodyfilePath = Directory.EnumerateFiles(
            rootPath, "bodyfile.txt", SearchOption.AllDirectories).FirstOrDefault();

        if (string.IsNullOrEmpty(bodyfilePath))
        {
            _log($"[{collectionName}] Body file not found — skipping.");
            return;
        }

        _log($"[{collectionName}] Processing body file…");

        var parsed = BodyFileProcessor.ProcessBodyFile(bodyfilePath, outputDir);

        QuickWinsHeader.EnsureHeader(outputDir, DateTime.UtcNow, parsed.FirstLogUtc, parsed.LastLogUtc);
        // Parsed data (the scored file timeline) goes next to the normalised logs in Processed\<collection>
        QuickWinsAppend.WriteProcessedBodyFileCsv(_processedDir, parsed);
        QuickWinsAppend.AppendBodyFileFindings(outputDir, parsed.Findings);
        foreach (var f in parsed.Findings)
            _collectedFindings.Add(("BODYFILE", f));
        _sourceInfos.Add(new CoverageTable.SourceInfo("BODYFILE", 1,
            parsed.FirstLogUtc ?? DateTime.MaxValue, parsed.LastLogUtc ?? DateTime.MinValue));

        _log($"[{collectionName}] Body file done.");
    }

    // ── hash_executables.sha1 ────────────────────────────────────────
    public const string Sha1CandidatesFile = "Sha1Candidates.csv";
    private const int MaxHashFindings = 100;

    /// <summary>
    /// UAC's hash_executables.sha1 (sha1sum output for every executable):
    /// scores each path (staging folder, hidden, suspicious name or
    /// extension), writes every candidate to Sha1Candidates.csv for a
    /// threat-intel lookup, and the top ones as findings.
    /// </summary>
    private void ProcessHashes(string collectionName, string rootPath, string outputDir)
    {
        var file = Directory.EnumerateFiles(rootPath, "hash_executables.sha1", SearchOption.AllDirectories).FirstOrDefault();
        if (file == null)
        {
            _log($"[{collectionName}] hash_executables.sha1 not found — skipping.");
            return;
        }

        var (candidates, stats) = new Sha1CandidateScorer().Score(file);
        _log($"[{collectionName}] SHA1 hashes: {stats}");

        using (var w = new StreamWriter(Path.Combine(outputDir, Sha1CandidatesFile), false, new System.Text.UTF8Encoding(false)))
        {
            w.WriteLine("Sha1,Path,Score,Reasons");
            foreach (var c in candidates)
                w.WriteLine(Reporting.Csv.Row(c.Hash.ToLowerInvariant(), c.Path, c.Score.ToString(CultureInfo.InvariantCulture), c.Reasons));
        }

        // Score 3–4: staging path or odd name alone; 5–6: two signals; 7+: e.g. hidden script in /tmp
        static string Sev(int score) => score >= 7 ? "HIGH" : score >= 5 ? "MEDIUM" : "SUSPICIOUS";
        var findings = candidates.Take(MaxHashFindings)
            .Select(c => $"[HASHES] [{Sev(c.Score)}] Executable worth a hash lookup: {c.Path} sha1={c.Hash.ToLowerInvariant()} (score {c.Score}: {c.Reasons})")
            .ToList();
        if (candidates.Count > MaxHashFindings)
            findings.Add($"[HASHES] [LOW] {candidates.Count - MaxHashFindings} more candidate(s) — see {Sha1CandidatesFile}");

        QuickWinsSectionWriter.WriteSection(Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile), "HASHES",
            $"No executables outside system folders worth a hash lookup ({stats.TotalLines:N0} hashed).",
            new List<(string FileName, List<string> Findings)> { (Path.GetFileName(file), findings) });
        foreach (var f in findings) _collectedFindings.Add(("HASHES", f));
        // No event times: the file lists what was on disk at collection
        _sourceInfos.Add(new CoverageTable.SourceInfo("HASHES", 1, DateTime.MaxValue, DateTime.MinValue));
        _log($"[{collectionName}] SHA1 hashes: {candidates.Count} candidate(s) → {Sha1CandidatesFile}");
    }

    // ── Reflection helpers (mirrors Form1) ────────────────────────────
    private static void TryAttach(object target, SessionTracker tracker)
    {
        var m = target.GetType().GetMethod("AttachSessionTracker", new[] { typeof(SessionTracker) });
        m?.Invoke(target, new object[] { tracker });
    }

    // ── User history parser helper ────────────────────────────────────
    // Shared block used by all user-history parsers (Zsh, VimInfo, DB, Python,
    // WgetHsts, LessHst). Handles discovery, parsing, QuickWins writing, and
    // stats population so each parser only needs a one-liner call site.
    private void RunUserHistoryBlock(
        string logKey,
        string collectionName,
        string outputDir,
        string hostname,
        List<(string FilePath, string Username)> files,
        Func<string, string, (List<string> Findings, Dictionary<string, int> Patterns, DateTime First, DateTime Last)> parseFile,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        if (files.Count == 0)
        {
            _log($"[{collectionName}] {logKey}: no files found — skipping.");
            return;
        }

        _log($"[{collectionName}] Parsing {files.Count} {logKey} file(s)…");

        var allFindings = new List<string>();
        var perFileFindings = new List<(string File, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        DateTime blockFirst = DateTime.MaxValue, blockLast = DateTime.MinValue;

        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        foreach (var (filePath, username) in files)
        {
            _log($"Parsing {logKey}: {username}");
            var (findings, patterns, first, last) = parseFile(filePath, username);

            perFileTimestamps[logKey][username] = (first, last);

            if (findings.Count > 0)
                perFileFindings.Add((filePath, findings));

            allFindings.AddRange(findings);

            foreach (var kv in patterns)
                combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                    ? ex + kv.Value : kv.Value;

            if (first != DateTime.MaxValue && first < blockFirst) blockFirst = first;
            if (last != DateTime.MinValue && last > blockLast) blockLast = last;
        }

        if (perFileFindings.Count > 0)
        {
            var quickWinsFile = Path.Combine(outputDir, Reporting.HostReport.QuickWinsFile);
            QuickWinsSectionWriter.WriteSection(
                quickWinsFile, logKey, "No suspicious activity detected.",
                perFileFindings.Select(pf => (FileName: pf.File, pf.Findings)).ToList());
        }

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (blockFirst, blockLast);
        ipLogs[logKey] = new Dictionary<string, int>();
        fileCounts[logKey] = files.Count;
    }

    /// <summary>
    /// All normalized CSV writers go through here so every Normalized_*.csv
    /// for a collection gets the same, resolved Hostname on every row.
    /// </summary>
    private NormalizedCsvWriter CreateCsv(string csvPath, bool append = false)
        => new NormalizedCsvWriter(csvPath, append) { Hostname = _currentHostname };

    private static void TryAttach(object target, NormalizedCsvWriter writer)
    {
        var m = target.GetType().GetMethod("AttachNormalizedWriter", new[] { typeof(NormalizedCsvWriter) });
        m?.Invoke(target, new object[] { writer });
    }

    private static void TryAttach(object target, string hostname)
    {
        var m = target.GetType().GetMethod("AttachHostname", new[] { typeof(string) });
        m?.Invoke(target, new object[] { hostname });
    }

    /// <summary>
    /// Finds all systemd journal files under rootPath:
    ///   system.journal, system@&lt;seq&gt;.journal       (system, active/archived)
    ///   user-&lt;uid&gt;.journal, user-&lt;uid&gt;@&lt;seq&gt;.journal (per user)
    ///   *.journal~                                  (dirty / unclean shutdown)
    /// Covers both /var/log/journal (persistent) and /run/log/journal (volatile).
    /// </summary>
    internal static List<string> DiscoverJournalFiles(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
            return new List<string>();

        return Directory.EnumerateFiles(rootPath, "*.journal*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".journal", StringComparison.OrdinalIgnoreCase)
                     || f.EndsWith(".journal~", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Derives the machine hostname from a UAC collection folder name.
    /// UAC naming convention: uac-&lt;hostname&gt;-YYYYMMDDHHmmss
    /// Falls back to the raw collection name if the pattern doesn't match.
    /// </summary>
    private static string ExtractHostnameFromCollection(string collectionName)
    {
        if (string.IsNullOrWhiteSpace(collectionName)) return string.Empty;
        var m = Regex.Match(collectionName,
            // Default UAC naming is uac-<host>-<os>-<timestamp>; strip the OS token.
            @"^uac-(?<host>.+?)(?:-(?:linux|aix|freebsd|macos|netbsd|netscaler|openbsd|solaris|esxi|android))?-\d{14}$",
            RegexOptions.IgnoreCase);
        return m.Success ? m.Groups["host"].Value : collectionName;
    }
}