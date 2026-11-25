using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using CsirtTriage.Core;
using CsirtTriage.Core.Case;
using CsirtTriage.Core.Kape;

namespace CsirtTriage.WPF.ViewModels;

public class MainViewModel : ViewModelBase
{
    public TriageSettings Settings { get; } = new();

    // ── Navigation ───────────────────────────────────────────────────
    private string _activePanel = "Case";
    public string ActivePanel { get => _activePanel; set => SetField(ref _activePanel, value); }
    public ICommand NavigateCommand { get; }

    // ── Case ─────────────────────────────────────────────────────────
    public string CaseName
    {
        get => Settings.CaseName;
        set { Settings.CaseName = value ?? ""; OnPropertyChanged(); }
    }
    public string Analyst
    {
        get => Settings.Analyst;
        set { Settings.Analyst = value ?? ""; OnPropertyChanged(); }
    }
    public string CaseFolder
    {
        get => Settings.CaseFolder;
        set
        {
            var v = (value ?? "").Trim().Trim('"');
            if (Settings.CaseFolder == v) return;
            Settings.CaseFolder = v;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasCase));
            if (HasCase) { LoadIocs(); _ = ScanAsync(); }
        }
    }
    public bool HasCase => !string.IsNullOrWhiteSpace(Settings.CaseFolder) && Directory.Exists(Settings.CaseFolder);

    // ── Collections ──────────────────────────────────────────────────
    public ObservableCollection<CollectionRow> Collections { get; } = new();
    private bool _isScanning;
    public bool IsScanning { get => _isScanning; private set => SetField(ref _isScanning, value); }
    private string _scanStatus = "Choose the case folder. It is searched for UAC archives and collections, KAPE output from the ORC processing script, and M365 audit log exports in Uploads\\M365.";
    public string ScanStatus { get => _scanStatus; private set => SetField(ref _scanStatus, value); }

    /// <summary>"Extract + analyse 2 · analyse 5 · re-analyse 1", for the run button.</summary>
    public string SelectionSummary
    {
        get
        {
            var sel = Collections.Where(c => c.IsSelected).ToList();
            if (sel.Count == 0) return "Nothing selected";
            var parts = sel.GroupBy(c => c.Entry.ActionLabel).Select(g => $"{g.Key}: {g.Count()}");
            var extract = sel.Where(c => c.Entry.Status == CollectionStatus.NotExtracted).ToList();
            long bytes = extract.Sum(c => c.Entry.SizeBytes ?? 0);
            return string.Join(Environment.NewLine, parts)
                   + (bytes > 0 ? $"{Environment.NewLine}{CollectionRow.FormatSize(bytes)} of archives to extract" : "");
        }
    }
    public int SelectedCount => Collections.Count(c => c.IsSelected);
    public string RunButtonText => IsRunning ? "Running…" : SelectedCount == 0 ? "▶  Run" : $"▶  Run {SelectedCount} collection(s)";

    public ICommand BrowseCommand { get; }
    public ICommand RescanCommand { get; }
    public ICommand SelectAllCommand { get; }
    public ICommand SelectNoneCommand { get; }
    public ICommand SelectNewCommand { get; }
    public ICommand OpenCaseFolderCommand { get; }
    public ICommand OpenResultsCommand { get; }

    // ── Run ──────────────────────────────────────────────────────────
    private bool _isRunning;
    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (SetField(ref _isRunning, value))
            {
                OnPropertyChanged(nameof(CanRun));
                OnPropertyChanged(nameof(RunButtonText));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
    public bool CanRun => !IsRunning && HasCase;
    private string _runStatus = "Ready";
    public string RunStatus { get => _runStatus; private set => SetField(ref _runStatus, value); }
    public ICommand RunCommand { get; }
    public ICommand CancelCommand { get; }
    private CancellationTokenSource? _cts;
    private CaseRunner? _runner;

    // Parallelism (Settings panel)
    public int MaxParallel
    {
        get => Settings.MaxParallel;
        set { Settings.MaxParallel = Math.Clamp(value, 1, 32); OnPropertyChanged(); }
    }
    public int MaxParallelExtractions
    {
        get => Settings.MaxParallelExtractions;
        set { Settings.MaxParallelExtractions = Math.Clamp(value, 1, 8); OnPropertyChanged(); }
    }
    public string ParallelHint => $"This computer has {Environment.ProcessorCount} logical cores. Large KAPE collections ($MFT, $J, event logs) need memory: lower this if the machine starts swapping.";

    // Date filter (applies to both pipelines)
    public DateTime? FilterFrom
    {
        get => Settings.Uac.FilterFrom;
        set { Settings.Uac.FilterFrom = Settings.Kape.FilterFrom = value; OnPropertyChanged(); }
    }
    public DateTime? FilterTo
    {
        get => Settings.Uac.FilterTo;
        set { Settings.Uac.FilterTo = Settings.Kape.FilterTo = value; OnPropertyChanged(); }
    }

    // ── Log (buffered: worker threads queue, a timer moves batches to the UI) ──
    private const int MaxLogEntries = 50_000;
    private readonly ConcurrentQueue<LogEntry> _pendingLog = new();
    private readonly DispatcherTimer _logTimer;
    public ObservableCollection<LogEntry> LogEntries { get; } = new();
    public ICollectionView LogView { get; }
    public ObservableCollection<string> LogFilters { get; } = new() { AllLog, CaseLog };
    public const string AllLog = "All collections";
    public const string CaseLog = "Case-wide only";
    private string _logFilter = AllLog;
    public string LogFilter { get => _logFilter; set { if (SetField(ref _logFilter, value ?? AllLog)) LogView.Refresh(); } }
    private bool _problemsOnly;
    public bool ProblemsOnly { get => _problemsOnly; set { if (SetField(ref _problemsOnly, value)) LogView.Refresh(); } }

    // ── Sources and settings ─────────────────────────────────────────
    public List<SourceToggle> Sources { get; }
    public ICollectionView UacSources { get; }
    public ICollectionView KapeSources { get; }
    public ICollectionView M365Sources { get; }
    public ICommand AllSourcesCommand { get; }
    public ICommand NoSourcesCommand { get; }

    public string Rank1KeywordsText { get => Lines(Settings.Uac.Rank1Keywords); set => SetLines(Settings.Uac.Rank1Keywords, value); }
    public string Rank2KeywordsText { get => Lines(Settings.Uac.Rank2Keywords); set => SetLines(Settings.Uac.Rank2Keywords, value); }
    public string UacWhitelistText { get => Lines(Settings.Uac.WhitelistPatterns); set => SetLines(Settings.Uac.WhitelistPatterns, value); }
    public string BodyFileKeywordsText { get => Lines(Settings.Uac.BodyFileSuspiciousKeywords); set => SetLines(Settings.Uac.BodyFileSuspiciousKeywords, value); }
    public string BodyFileWhitelistText { get => Lines(Settings.Uac.BodyFileWhitelistPrefixes); set => SetLines(Settings.Uac.BodyFileWhitelistPrefixes, value); }
    public string KapeKeywordsText { get => Lines(Settings.Kape.ExtraKeywords); set => SetLines(Settings.Kape.ExtraKeywords, value); }
    public string KapeWhitelistText { get => Lines(Settings.Kape.WhitelistPaths); set => SetLines(Settings.Kape.WhitelistPaths, value); }
    private static string Lines(IEnumerable<string> list) => string.Join(Environment.NewLine, list);
    private static void SetLines(ObservableCollection<string> list, string text)
    {
        list.Clear();
        foreach (var l in (text ?? "").Split('\n').Select(s => s.Trim()).Where(s => s.Length > 0)) list.Add(l);
    }

    // Detection rules file (KAPE)
    /// <summary>
    /// The rules file in use, filled in with the default (rules.json next to
    /// CsirtTriage.exe) so the field always shows which file applies. Clearing
    /// the field, or entering the default, goes back to the default.
    /// </summary>
    public string RulesPathText
    {
        get => string.IsNullOrWhiteSpace(Settings.Kape.RulesPath) ? RuleSet.DefaultPath : Settings.Kape.RulesPath;
        set
        {
            var v = (value ?? "").Trim().Trim('"');
            bool isDefault = v.Length == 0 || string.Equals(Path.GetFullPath(v), Path.GetFullPath(RuleSet.DefaultPath), StringComparison.OrdinalIgnoreCase);
            Settings.Kape.RulesPath = isDefault ? "" : v;
            OnPropertyChanged();
            ReloadRules();
        }
    }
    private string _rulesStatus = "";
    public string RulesStatus { get => _rulesStatus; private set => SetField(ref _rulesStatus, value); }
    private bool _rulesOk = true;
    public bool RulesOk { get => _rulesOk; private set => SetField(ref _rulesOk, value); }
    public ICommand ReloadRulesCommand { get; }
    public ICommand BrowseRulesCommand { get; }
    public ICommand OpenRulesCommand { get; }

    // ── IOCs ─────────────────────────────────────────────────────────
    private string _iocText = "";
    private bool _iocDirty;
    public string IocText
    {
        get => _iocText;
        set { if (SetField(ref _iocText, value ?? "")) { _iocDirty = true; UpdateIocPreview(); } }
    }
    private string _iocPreview = "No IOCs yet — paste a list above.";
    public string IocPreview { get => _iocPreview; private set => SetField(ref _iocPreview, value); }
    private string _iocRejected = "";
    public string IocRejected { get => _iocRejected; private set => SetField(ref _iocRejected, value); }
    private string _iocStatus = "";
    public string IocStatus { get => _iocStatus; private set => SetField(ref _iocStatus, value); }
    private string _discoveredLabel = "Load discovered";
    public string DiscoveredLabel { get => _discoveredLabel; private set => SetField(ref _discoveredLabel, value); }
    public ICommand SaveIocsCommand { get; }
    public ICommand SearchIocsCommand { get; }
    public ICommand ImportIocsCommand { get; }
    public ICommand LoadDiscoveredCommand { get; }

    // ── Panels with their own view model ─────────────────────────────
    public CaseReportViewModel Report { get; }
    public FindingsViewModel Findings { get; }

    public MainViewModel()
    {
        Report = new CaseReportViewModel(Settings);
        Findings = new FindingsViewModel(Settings);
        Settings.Analyst = Environment.UserName;

        Sources = SourceCatalog.Create(Settings);
        UacSources = Grouped(Sources.Where(s => s.Kind == CollectionKind.Uac));
        KapeSources = Grouped(Sources.Where(s => s.Kind == CollectionKind.Kape));
        M365Sources = Grouped(Sources.Where(s => s.Kind == CollectionKind.M365));
        AllSourcesCommand = new RelayCommand(p => SetSources(p as string, true));
        NoSourcesCommand = new RelayCommand(p => SetSources(p as string, false));

        LogView = CollectionViewSource.GetDefaultView(LogEntries);
        LogView.Filter = o => LogMatches((LogEntry)o);
        _logTimer = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Background, (_, _) => FlushLog(),
                                        System.Windows.Application.Current.Dispatcher);
        _logTimer.Start();

        NavigateCommand = new RelayCommand(p =>
        {
            if (ActivePanel == "Report") Report.SaveIfDirty();
            ActivePanel = p as string ?? ActivePanel;
            if (ActivePanel == "Report") Report.EnsureLoaded();
            if (ActivePanel == "Findings") Findings.EnsureLoaded();
        });

        BrowseCommand = new RelayCommand(_ => BrowseCase());
        RescanCommand = new RelayCommand(_ => _ = ScanAsync(), _ => HasCase && !IsRunning);
        SelectAllCommand = new RelayCommand(_ => Select(r => r.CanSelect), _ => !IsRunning);
        SelectNoneCommand = new RelayCommand(_ => Select(_ => false), _ => !IsRunning);
        SelectNewCommand = new RelayCommand(_ => Select(r => r.Entry.SelectedByDefault), _ => !IsRunning);
        OpenCaseFolderCommand = new RelayCommand(_ => OpenFolder(Settings.CaseFolder), _ => HasCase);
        OpenResultsCommand = new RelayCommand(_ => OpenFolder(Settings.ResultsRoot), _ => HasCase);

        RunCommand = new RelayCommand(_ => _ = RunAsync(), _ => CanRun && SelectedCount > 0);
        CancelCommand = new RelayCommand(_ => { _cts?.Cancel(); RunStatus = "Cancelling…"; }, _ => IsRunning);

        ReloadRulesCommand = new RelayCommand(_ => ReloadRules());
        BrowseRulesCommand = new RelayCommand(_ => BrowseRules());
        OpenRulesCommand = new RelayCommand(_ => OpenRules());
        ReloadRules();

        SaveIocsCommand = new RelayCommand(_ => SaveIocs());
        SearchIocsCommand = new RelayCommand(_ => _ = SearchIocsAsync(), _ => CanRun);
        ImportIocsCommand = new RelayCommand(_ => BrowseIocFile());
        LoadDiscoveredCommand = new RelayCommand(_ => LoadDiscovered());
    }

    private static ICollectionView Grouped(IEnumerable<SourceToggle> items)
    {
        var view = new ListCollectionView(items.ToList());
        view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(SourceToggle.Category)));
        return view;
    }

    private void SetSources(string? kind, bool on)
    {
        foreach (var s in Sources.Where(s => kind == null || s.Kind.ToString().Equals(kind, StringComparison.OrdinalIgnoreCase)))
            s.IsEnabled = on;
    }

    // ── Case folder and scan ─────────────────────────────────────────
    private void BrowseCase()
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select the case folder (with Uploads\\, Decompressed\\ and Processed\\)",
            UseDescriptionForTitle = true,
            SelectedPath = HasCase ? Settings.CaseFolder : "",
        };
        if (dlg.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
        if (string.IsNullOrWhiteSpace(CaseName)) CaseName = Path.GetFileName(dlg.SelectedPath.TrimEnd('\\', '/'));
        CaseFolder = dlg.SelectedPath;
    }

    private async Task ScanAsync()
    {
        if (!HasCase) return;
        IsScanning = true;
        ScanStatus = "Scanning the case folder…";
        var folder = Settings.CaseFolder;
        List<CollectionEntry> entries;
        try { entries = await Task.Run(() => CollectionScanner.Scan(folder)); }
        catch (Exception ex) { ScanStatus = $"Scan failed: {ex.Message}"; IsScanning = false; return; }
        if (folder != Settings.CaseFolder) return;   // the case changed while scanning

        Collections.Clear();
        foreach (var e in entries) Collections.Add(new CollectionRow(e, SelectionChanged, name => _runner?.Cancel(name)));

        var uac = entries.Count(e => e.Kind == CollectionKind.Uac);
        var kape = entries.Count(e => e.Kind == CollectionKind.Kape && e.Status != CollectionStatus.WaitingForKape);
        var m365 = entries.Count(e => e.Kind == CollectionKind.M365);
        var waiting = entries.Count(e => e.Status == CollectionStatus.WaitingForKape);
        ScanStatus = entries.Count == 0
            ? "No collections found. Expected UAC archives in Uploads\\, collections in Decompressed\\, KAPE output in Processed\\ or M365 audit log exports in Uploads\\M365\\."
            : $"{entries.Count} collection(s): {uac} UAC, {kape} KAPE" + (m365 > 0 ? $", {m365} M365" : "") + (waiting > 0 ? $", {waiting} waiting for the ORC processing script" : "") + ".";
        foreach (var name in LogFilters.Skip(2).ToList()) LogFilters.Remove(name);
        foreach (var e in entries) LogFilters.Add(e.Name);
        IsScanning = false;
        SelectionChanged();
        RefreshDiscoveredLabel();
    }

    private void Select(Func<CollectionRow, bool> pick)
    {
        foreach (var r in Collections) r.IsSelected = pick(r);
    }

    private void SelectionChanged()
    {
        OnPropertyChanged(nameof(SelectionSummary));
        OnPropertyChanged(nameof(SelectedCount));
        OnPropertyChanged(nameof(RunButtonText));
        CommandManager.InvalidateRequerySuggested();
    }

    private static void OpenFolder(string path)
    {
        if (Directory.Exists(path)) Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true });
    }

    // ── Run ──────────────────────────────────────────────────────────
    private async Task RunAsync()
    {
        if (!HasCase) { ActivePanel = "Case"; ScanStatus = "Choose a case folder first."; return; }
        var selected = Collections.Where(c => c.IsSelected).ToList();
        if (selected.Count == 0) return;
        if (_iocDirty) SaveIocs();
        Report.SaveIfDirty();

        IsRunning = true;
        RunStatus = $"Running {selected.Count} collection(s), up to {Settings.MaxParallel} at a time…";
        foreach (var r in Collections) r.ResetJob();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _runner = new CaseRunner(Settings, (collection, m) => Log(m, Level(m), collection));
        var rows = Collections.ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);
        var progress = new Progress<JobUpdate>(u => { if (rows.TryGetValue(u.Name, out var row)) row.Apply(u); });

        try
        {
            Log($"Case: {Settings.CaseName}   Analyst: {Settings.Analyst}   Folder: {Settings.CaseFolder}");
            var result = await Task.Run(() => _runner.RunAsync(selected.Select(r => r.Entry).ToList(), progress, _cts.Token));
            RunStatus = $"Done: {result.Done} analysed" + (result.Failed > 0 ? $", {result.Failed} failed" : "") +
                        (result.Cancelled > 0 ? $", {result.Cancelled} cancelled" : "") + ".";
            Log(RunStatus, result.Failed > 0 ? LogLevel.Warning : LogLevel.Success);
        }
        catch (OperationCanceledException)
        {
            RunStatus = "Run cancelled.";
            Log(RunStatus, LogLevel.Warning);
        }
        catch (Exception ex)
        {
            RunStatus = $"Run failed: {ex.Message}";
            Log(RunStatus, LogLevel.Error);
        }
        finally
        {
            _runner = null;
            IsRunning = false;
            FlushLog();
            // Keep the job results on screen; a rescan shows the new statuses
            var states = Collections.Where(r => r.Job is JobState.Failed or JobState.Cancelled)
                .ToDictionary(r => r.Name, r => new JobUpdate(r.Name, r.Job!.Value, r.JobMessage), StringComparer.OrdinalIgnoreCase);
            await ScanAsync();
            foreach (var r in Collections)
                if (states.TryGetValue(r.Name, out var u)) r.Apply(u);
            Findings.EnsureLoaded();
        }
    }

    private static LogLevel Level(string m) =>
        m.StartsWith("[ERROR]") ? LogLevel.Error : m.StartsWith("[WARN]") ? LogLevel.Warning : LogLevel.Info;

    /// <summary>Thread-safe: queues the line; the UI shows it within a quarter second.</summary>
    public void Log(string message, LogLevel level = LogLevel.Info, string? collection = null) =>
        _pendingLog.Enqueue(new LogEntry(DateTime.Now, message, level, collection));

    private void FlushLog()
    {
        if (_pendingLog.IsEmpty) return;
        int n = 0;
        while (n < 5000 && _pendingLog.TryDequeue(out var e)) { LogEntries.Add(e); n++; }
        while (LogEntries.Count > MaxLogEntries) LogEntries.RemoveAt(0);
    }

    private bool LogMatches(LogEntry e) =>
        (!ProblemsOnly || e.Level is LogLevel.Warning or LogLevel.Error)
        && (LogFilter == AllLog
            || LogFilter == CaseLog && e.Collection == null
            || e.Collection != null && e.Collection.Equals(LogFilter, StringComparison.OrdinalIgnoreCase));

    // ── Rules ────────────────────────────────────────────────────────
    private void ReloadRules()
    {
        var path = Settings.Kape.ResolveRulesPath();
        RulesOk = RuleSet.TryLoad(path, out var message);
        RulesStatus = RulesOk ? $"Loaded {message}" : $"Not loaded — {message}";
    }

    private void BrowseRules()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Detection rules file", Filter = "Rules (*.json)|*.json|All files (*.*)|*.*",
            FileName = Path.GetFileName(Settings.Kape.ResolveRulesPath()),
            InitialDirectory = Path.GetDirectoryName(Settings.Kape.ResolveRulesPath()),
        };
        if (dlg.ShowDialog() == true) RulesPathText = dlg.FileName;
    }

    private void OpenRules()
    {
        var path = Settings.Kape.ResolveRulesPath();
        if (!File.Exists(path)) { RulesOk = false; RulesStatus = $"Not found: {path}"; return; }
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch { Process.Start(new ProcessStartInfo("notepad.exe", $"\"{path}\"") { UseShellExecute = true }); }
    }

    // ── IOCs ─────────────────────────────────────────────────────────
    private void LoadIocs()
    {
        if (!HasCase) return;
        var p = CaseIocs.PathFor(Settings.CaseFolder);
        _iocText = File.Exists(p) ? File.ReadAllText(p) : "";
        OnPropertyChanged(nameof(IocText));
        _iocDirty = false;
        UpdateIocPreview();
        IocStatus = File.Exists(p) ? $"Loaded {p}" : $"No IOC list yet — it will be saved to {p}";
    }

    private void UpdateIocPreview()
    {
        var (iocs, rejected) = CaseIocs.Parse(_iocText);
        IocPreview = iocs.Count == 0 ? "No IOCs recognised yet." : CaseIocs.Summary(iocs);
        IocRejected = rejected.Count > 0
            ? $"{rejected.Count} line(s) without an IOC (dropped on save): {string.Join("  |  ", rejected.Take(3))}{(rejected.Count > 3 ? "  | …" : "")}"
            : "";
    }

    private bool SaveIocs()
    {
        if (!HasCase) { IocStatus = "Choose a case folder first (Case)."; return false; }
        var (iocs, rejected) = CaseIocs.Parse(_iocText);
        try { CaseIocs.Save(Settings.CaseFolder, iocs, Settings.CaseName); }
        catch (Exception ex) { IocStatus = $"Could not save: {ex.Message}"; return false; }
        _iocText = CaseIocs.Format(iocs, Settings.CaseName);
        OnPropertyChanged(nameof(IocText));
        _iocDirty = false;
        UpdateIocPreview();
        IocStatus = $"Saved {iocs.Count} IOC(s) to {CaseIocs.PathFor(Settings.CaseFolder)}" +
                    (rejected.Count > 0 ? $" — {rejected.Count} line(s) without an IOC dropped." : ".");
        return true;
    }

    private void BrowseIocFile()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Import IOCs",
            Filter = "IOC lists (*.txt;*.csv;*.tsv;*.ioc)|*.txt;*.csv;*.tsv;*.ioc|All files (*.*)|*.*",
            Multiselect = true,
        };
        if (dlg.ShowDialog() == true)
            foreach (var f in dlg.FileNames) ImportIocFile(f);
    }

    /// <summary>Appends the IOCs found in a file (txt, CSV/MISP export, …) to the list.</summary>
    public void ImportIocFile(string path)
    {
        try
        {
            var (iocs, rejected) = CaseIocs.Parse(File.ReadAllText(path));
            if (iocs.Count == 0) { IocStatus = $"No IOCs found in {Path.GetFileName(path)}."; return; }
            AppendIocBlock($"imported from {Path.GetFileName(path)}", iocs.Select(i => i.ToLine()));
            IocStatus = $"Imported {iocs.Count} IOC(s) from {Path.GetFileName(path)}" +
                        (rejected.Count > 0 ? $" ({rejected.Count} line(s) without an IOC skipped)" : "") + " — review, then Save.";
        }
        catch (Exception ex) { IocStatus = $"Import failed: {ex.Message}"; }
    }

    private void LoadDiscovered()
    {
        if (!HasCase) { IocStatus = "Choose a case folder first (Case)."; return; }
        var p = Path.Combine(Settings.ResultsRoot, CaseIocs.DiscoveredFileName);
        if (!File.Exists(p)) { IocStatus = "No discovered IOCs yet — run the analysis first."; return; }
        var current = new HashSet<string>(CaseIocs.Parse(_iocText).Iocs.Select(i => i.Value), StringComparer.OrdinalIgnoreCase);
        var lines = File.ReadAllLines(p)
            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith('#'))
            .Where(l => CaseIocs.Parse(l).Iocs.Any(i => !current.Contains(i.Value)))
            .ToList();
        if (lines.Count == 0) { IocStatus = "All discovered IOCs are already in the list."; return; }
        AppendIocBlock("discovered in findings — delete lines you don't trust, then Save", lines);
        IocStatus = $"Added {lines.Count} discovered IOC(s) at the bottom — review them, then Save and Search.";
    }

    private void RefreshDiscoveredLabel()
    {
        var p = Path.Combine(Settings.ResultsRoot, CaseIocs.DiscoveredFileName);
        int n = File.Exists(p) ? File.ReadLines(p).Count(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith('#')) : 0;
        DiscoveredLabel = n > 0 ? $"Load discovered ({n})" : "Load discovered";
    }

    private void AppendIocBlock(string title, IEnumerable<string> lines)
    {
        var sb = new System.Text.StringBuilder(_iocText.TrimEnd());
        if (sb.Length > 0) sb.AppendLine().AppendLine();
        sb.AppendLine($"# ── {title} ──");
        foreach (var l in lines) sb.AppendLine(l);
        IocText = sb.ToString();
    }

    private async Task SearchIocsAsync()
    {
        if (_iocDirty && !SaveIocs()) return;
        if (!HasCase) return;
        if (!Directory.Exists(Settings.ResultsRoot))
        {
            IocStatus = "Nothing analysed yet — run the analysis first; it searches the IOC list automatically.";
            return;
        }
        IsRunning = true;
        IocStatus = "Searching analysed collections…";
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        Settings.Sync();
        try
        {
            Log("IOC search started (analysed output only — no re-analysis).");
            var result = await Task.Run(() => CaseFinisher.Finish(Settings.CaseFolder, Settings.ResultsRoot,
                Settings.CaseName, Settings.Analyst, m => Log(m, Level(m)), ct), ct);
            IocStatus = result.IocCount == 0
                ? "The IOC list is empty — earlier hits were removed."
                : result.IocsHit == 0
                    ? $"None of the {result.IocCount} IOC(s) were seen in {result.CollectionsSearched} collection(s)."
                    : $"{result.IocsHit} of {result.IocCount} IOC(s) seen on {result.CollectionsWithHits} of {result.CollectionsSearched} collection(s) " +
                      "→ CASE IOC HITS at the top of each QuickWins.rtf, IocHits.csv and CaseSummary.txt.";
            Log("IOC search done.", LogLevel.Success);
        }
        catch (OperationCanceledException) { IocStatus = "IOC search cancelled."; }
        catch (Exception ex) { IocStatus = $"IOC search failed: {ex.Message}"; }
        finally
        {
            IsRunning = false;
            RefreshDiscoveredLabel();
            Findings.EnsureLoaded();
        }
    }
}

public enum LogLevel { Info, Success, Warning, Error }

public record LogEntry(DateTime Timestamp, string Message, LogLevel Level, string? Collection = null)
{
    // Lines from the parsers don't name their collection; with several running at once they need to
    public string Display => Collection != null && !Message.Contains($"[{Collection}]", StringComparison.OrdinalIgnoreCase)
        ? $"[{Timestamp:HH:mm:ss}] [{Collection}] {Message}"
        : $"[{Timestamp:HH:mm:ss}] {Message}";
}
