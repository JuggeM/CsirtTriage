using System.Collections.Concurrent;
using CsirtTriage.Core.Kape;
using CsirtTriage.Core.Uac;

namespace CsirtTriage.Core.Case;

/// <summary>Everything a run needs: the case, the two pipelines' settings and the parallelism limits.</summary>
public sealed class TriageSettings
{
    public string CaseFolder { get; set; } = "";
    public string CaseName { get; set; } = "";
    public string Analyst { get; set; } = "";
    public ParserConfig Uac { get; set; } = new();
    public AnalyserConfig Kape { get; set; } = new();
    public M365.M365Config M365 { get; set; } = new();
    public bool SearchIocs { get; set; } = true;

    /// <summary>Collections analysed at the same time. Default: half the CPU cores, at most 4.</summary>
    public int MaxParallel { get; set; } = DefaultParallel;
    /// <summary>Archives extracted at the same time; extraction is disk-bound, so 1 is usually fastest.</summary>
    public int MaxParallelExtractions { get; set; } = 1;

    public static int DefaultParallel => Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    public string ResultsRoot => Path.Combine(CaseFolder, CollectionScanner.ResultsFolder);

    /// <summary>Copies case, analyst and output folder into both pipelines' settings.</summary>
    public void Sync()
    {
        CaseFolder = Path.GetFullPath(CaseFolder);
        Uac.CaseFolderPath = Kape.CaseFolderPath = CaseFolder;
        Uac.CaseName = Kape.CaseName = CaseName;
        Uac.AnalystName = Kape.AnalystName = Analyst;
        Uac.OutputPath = Kape.OutputPath = CollectionScanner.ResultsFolder;
        Kape.SearchIocs = SearchIocs;
    }
}

public enum JobState { Queued, Extracting, Analysing, Done, Failed, Cancelled }

/// <summary>Progress of one collection's job, for the collections table.</summary>
public sealed record JobUpdate(string Name, JobState State, string Message = "", double? Fraction = null);

/// <summary>
/// Runs the selected collections: each is one job (UAC: extract if needed,
/// parse, analyse; KAPE: analyse), up to <see cref="TriageSettings.MaxParallel"/>
/// at a time. A failed or cancelled job does not stop the others. When the
/// jobs are done, the case-wide steps run once over every analysed collection.
/// </summary>
public sealed class CaseRunner
{
    private readonly TriageSettings _settings;
    private readonly Action<string?, string> _log;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _jobs = new(StringComparer.OrdinalIgnoreCase);

    public sealed record RunResult(int Done, int Failed, int Cancelled, CaseFinisher.Result? Case);

    /// <param name="log">Called with the collection name (null for case-wide messages) and the message. Called from worker threads.</param>
    public CaseRunner(TriageSettings settings, Action<string?, string> log)
    {
        _settings = settings;
        _log = log;
    }

    /// <summary>Cancels one running or queued job; the others continue.</summary>
    public void Cancel(string name)
    {
        if (_jobs.TryGetValue(name, out var cts)) cts.Cancel();
    }

    public async Task<RunResult> RunAsync(IReadOnlyList<CollectionEntry> selected, IProgress<JobUpdate>? progress,
                                          CancellationToken ct = default)
    {
        _settings.Sync();
        var runnable = selected.Where(e => e.CanRun).ToList();
        foreach (var e in selected.Where(e => !e.CanRun))
            _log(e.Name, $"[WARN] [{e.Name}] {e.StatusLabel} — skipped.");

        int done = 0, failed = 0, cancelled = 0;
        if (runnable.Count > 0)
        {
            Directory.CreateDirectory(_settings.ResultsRoot);
            if (runnable.Any(e => e.Kind is CollectionKind.Kape or CollectionKind.M365))
                new AnalysisEngine(_settings.Kape, m => _log(null, m)).LoadRules();

            foreach (var e in runnable)
            {
                _jobs[e.Name] = CancellationTokenSource.CreateLinkedTokenSource(ct);
                progress?.Report(new JobUpdate(e.Name, JobState.Queued));
            }

            using var extractGate = new SemaphoreSlim(Math.Max(1, _settings.MaxParallelExtractions));
            _log(null, $"Running {runnable.Count} collection(s), up to {_settings.MaxParallel} at a time.");
            var options = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, _settings.MaxParallel) };
            await Parallel.ForEachAsync(runnable, options, (entry, _) =>
            {
                var jobCt = _jobs[entry.Name].Token;
                var state = RunJob(entry, extractGate, progress, jobCt);
                if (state == JobState.Done) Interlocked.Increment(ref done);
                else if (state == JobState.Failed) Interlocked.Increment(ref failed);
                else Interlocked.Increment(ref cancelled);
                return ValueTask.CompletedTask;
            });
            foreach (var cts in _jobs.Values) cts.Dispose();
            _jobs.Clear();
        }

        CaseFinisher.Result? caseResult = null;
        if (!ct.IsCancellationRequested)
        {
            _log(null, "Case-wide steps: IOC search, case summary, case tracker…");
            caseResult = await Task.Run(() => CaseFinisher.Finish(_settings.CaseFolder, _settings.ResultsRoot,
                _settings.CaseName, _settings.Analyst, m => _log(null, m), ct, _settings.SearchIocs), ct);
        }
        _log(null, $"Run finished: {done} analysed, {failed} failed, {cancelled} cancelled.");
        return new RunResult(done, failed, cancelled, caseResult);
    }

    private JobState RunJob(CollectionEntry entry, SemaphoreSlim extractGate, IProgress<JobUpdate>? progress, CancellationToken ct)
    {
        void Log(string m) => _log(entry.Name, m);
        try
        {
            ct.ThrowIfCancellationRequested();
            if (entry.Status == CollectionStatus.Analysed) MoveAside(entry.Name, Log);

            if (entry.Kind == CollectionKind.Uac)
            {
                var root = entry.SourcePath;
                if (root == null)
                {
                    if (entry.ArchivePath == null) throw new InvalidOperationException("no archive and no extracted folder");
                    progress?.Report(new JobUpdate(entry.Name, JobState.Extracting, "waiting for a free extraction slot"));
                    extractGate.Wait(ct);
                    try
                    {
                        progress?.Report(new JobUpdate(entry.Name, JobState.Extracting));
                        Log($"[{entry.Name}] Extracting {Path.GetFileName(entry.ArchivePath)}…");
                        var decompressed = Path.Combine(_settings.CaseFolder, CollectionScanner.DecompressedFolder);
                        Directory.CreateDirectory(decompressed);
                        UacExtractor.Extract(entry.ArchivePath, decompressed, ct,
                            n => progress?.Report(new JobUpdate(entry.Name, JobState.Extracting, $"{n:N0} files")));
                    }
                    finally { extractGate.Release(); }
                    root = ParserOrchestrator.FindCollections(Path.Combine(_settings.CaseFolder, CollectionScanner.DecompressedFolder))
                        .GetValueOrDefault(entry.Name) ?? throw new InvalidOperationException("extracted folder not found");
                }
                progress?.Report(new JobUpdate(entry.Name, JobState.Analysing));
                // One orchestrator per collection: it keeps the collection's state while it runs
                new ParserOrchestrator(_settings.Uac, Log).AnalyseCollection(entry.Name, root, ct);
            }
            else if (entry.Kind == CollectionKind.M365)
            {
                if (entry.SourcePath == null) throw new InvalidOperationException("no audit log folder");
                progress?.Report(new JobUpdate(entry.Name, JobState.Analysing));
                new M365.M365Engine(_settings, Log).AnalyseCollection(entry.Name, entry.SourcePath, ct);
            }
            else
            {
                if (entry.SourcePath == null) throw new InvalidOperationException("no KAPE output");
                progress?.Report(new JobUpdate(entry.Name, JobState.Analysing));
                new AnalysisEngine(_settings.Kape, Log).AnalyseHost(new KapeHost(entry.Name, entry.SourcePath, 0), ct,
                    p => progress?.Report(new JobUpdate(entry.Name, JobState.Analysing, "", p)));
            }
            progress?.Report(new JobUpdate(entry.Name, JobState.Done));
            return JobState.Done;
        }
        catch (OperationCanceledException)
        {
            Log($"[WARN] [{entry.Name}] Cancelled.");
            progress?.Report(new JobUpdate(entry.Name, JobState.Cancelled));
            return JobState.Cancelled;
        }
        catch (Exception ex)
        {
            Log($"[ERROR] [{entry.Name}] {ex.Message}");
            progress?.Report(new JobUpdate(entry.Name, JobState.Failed, ex.Message));
            return JobState.Failed;
        }
    }

    /// <summary>
    /// Re-analysis keeps the earlier results: Level2\&lt;name&gt; moves to
    /// Level2\_previous\&lt;name&gt;-&lt;time&gt; (ignored by the case-wide steps).
    /// </summary>
    private void MoveAside(string name, Action<string> log)
    {
        var dir = Path.Combine(_settings.ResultsRoot, name);
        if (!Directory.Exists(dir)) return;
        var previous = Path.Combine(_settings.ResultsRoot, "_previous");
        Directory.CreateDirectory(previous);
        var target = Path.Combine(previous, $"{name}-{DateTime.Now:yyyyMMdd-HHmmss}");
        Directory.Move(dir, target);
        log($"[{name}] Earlier results kept in {target}");
    }
}
