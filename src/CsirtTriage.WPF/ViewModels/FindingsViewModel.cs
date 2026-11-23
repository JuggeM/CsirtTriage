using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Input;
using CsirtTriage.Core;
using CsirtTriage.Core.Case;
using CsirtTriage.Core.Reporting;

namespace CsirtTriage.WPF.ViewModels;

public sealed record FindingRow(DateTime? Time, string TimeText, string Host, string Collection, string Kind,
                                string Severity, int Rank, string Source, int Count, string Text, string Detail, string Artifact);

/// <summary>
/// The "Findings" panel: every collection's findings in one filterable grid,
/// so triage can start in the app instead of in one QuickWins file per host.
/// </summary>
public sealed class FindingsViewModel : ViewModelBase
{
    private readonly TriageSettings _settings;
    private DateTime _loadedStamp;
    private string? _loadedFor;

    public FindingsViewModel(TriageSettings settings)
    {
        _settings = settings;
        View = CollectionViewSource.GetDefaultView(Rows);
        View.Filter = o => Matches((FindingRow)o);
        RefreshCommand = new RelayCommand(_ => Load());
        ClearFiltersCommand = new RelayCommand(_ => { Search = ""; Host = All; Source = All; MinSeverity = "MEDIUM"; });
    }

    public const string All = "(all)";
    public ObservableCollection<FindingRow> Rows { get; } = new();
    public ICollectionView View { get; }
    public ObservableCollection<string> Hosts { get; } = new() { All };
    public ObservableCollection<string> Sources { get; } = new() { All };
    public string[] Severities { get; } = { "CRITICAL", "HIGH", "MEDIUM", "SUSPICIOUS", "LOW" };
    public ICommand RefreshCommand { get; }
    public ICommand ClearFiltersCommand { get; }

    private string _search = "";
    public string Search { get => _search; set { if (SetField(ref _search, value)) Apply(); } }
    private string _host = All;
    public string Host { get => _host; set { if (SetField(ref _host, value ?? All)) Apply(); } }
    private string _source = All;
    public string Source { get => _source; set { if (SetField(ref _source, value ?? All)) Apply(); } }
    private string _minSeverity = "MEDIUM";
    public string MinSeverity { get => _minSeverity; set { if (SetField(ref _minSeverity, value ?? "LOW")) Apply(); } }

    private string _status = "";
    public string Status { get => _status; private set => SetField(ref _status, value); }

    private FindingRow? _selected;
    public FindingRow? Selected { get => _selected; set => SetField(ref _selected, value); }

    private static int RankOf(string sev) => sev switch
    {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "SUSPICIOUS" => 3, _ => 4,
    };

    private bool Matches(FindingRow r) =>
        r.Rank <= RankOf(MinSeverity)
        && (Host == All || r.Host.Equals(Host, StringComparison.OrdinalIgnoreCase))
        && (Source == All || r.Source.Equals(Source, StringComparison.OrdinalIgnoreCase))
        && (Search.Length == 0
            || r.Text.Contains(Search, StringComparison.OrdinalIgnoreCase)
            || r.Detail.Contains(Search, StringComparison.OrdinalIgnoreCase)
            || r.Artifact.Contains(Search, StringComparison.OrdinalIgnoreCase));

    private void Apply()
    {
        View.Refresh();
        int shown = Rows.Count(Matches);
        Status = Rows.Count == 0 ? Status : $"{shown:N0} of {Rows.Count:N0} finding(s) shown.";
    }

    /// <summary>Loads again when the case changed or a run wrote new results since the last load.</summary>
    public void EnsureLoaded()
    {
        var root = _settings.ResultsRoot;
        var stamp = Stamp(root);
        if (_loadedFor != root || stamp > _loadedStamp) Load();
    }

    private static DateTime Stamp(string root)
    {
        var p = Path.Combine(root, CaseSummary.FileName);
        return File.Exists(p) ? File.GetLastWriteTimeUtc(p) : DateTime.MinValue;
    }

    public void Load()
    {
        Rows.Clear();
        var root = string.IsNullOrWhiteSpace(_settings.CaseFolder) ? "" : _settings.ResultsRoot;
        _loadedFor = root;
        _loadedStamp = Stamp(root);
        var hosts = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var sources = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (dir, info) in CaseFinisher.Collections(root))
        {
            bool header = true;
            // TimeUtc,LastUtc,Host,Severity,Source,Category,Count,Text,Detail,Artifact
            foreach (var line in IocSearch.SafeLines(Path.Combine(dir, HostReport.FindingsFile)))
            {
                if (header) { header = false; continue; }
                var f = IocSearch.SplitCsv(line);
                if (f.Count < 10) continue;
                var time = CaseSummary.ParseTime(f[0]);
                Rows.Add(new FindingRow(time, f[0], info.Hostname, info.Collection, info.KindLabel, f[3], RankOf(f[3]), f[4],
                    int.TryParse(f[6], out var n) ? n : 1, f[7], f[8], f[9]));
                hosts.Add(info.Hostname);
                sources.Add(f[4]);
            }
        }

        Hosts.Clear(); Hosts.Add(All); foreach (var h in hosts) Hosts.Add(h);
        Sources.Clear(); Sources.Add(All); foreach (var s in sources) Sources.Add(s);
        if (!Hosts.Contains(Host)) Host = All;
        if (!Sources.Contains(Source)) Source = All;

        using (View.DeferRefresh())
        {
            View.SortDescriptions.Clear();
            View.SortDescriptions.Add(new SortDescription(nameof(FindingRow.Rank), ListSortDirection.Ascending));
            View.SortDescriptions.Add(new SortDescription(nameof(FindingRow.TimeText), ListSortDirection.Ascending));
        }
        Status = Rows.Count == 0 ? "No findings yet. Run the analysis first." : "";
        Apply();
    }
}
