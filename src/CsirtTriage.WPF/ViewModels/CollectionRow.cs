using System.Windows.Input;
using CsirtTriage.Core.Case;

namespace CsirtTriage.WPF.ViewModels;

/// <summary>One row of the collections table: the scanned collection, whether it is ticked, and its job while a run is going.</summary>
public sealed class CollectionRow : ViewModelBase
{
    private readonly Action _selectionChanged;

    public CollectionRow(CollectionEntry entry, Action selectionChanged, Action<string> cancel)
    {
        Entry = entry;
        _selectionChanged = selectionChanged;
        _isSelected = entry.SelectedByDefault;
        CancelCommand = new RelayCommand(_ => cancel(entry.Name), _ => IsBusy);
    }

    public CollectionEntry Entry { get; }
    public string Name => Entry.Name;
    public string Host => Entry.Host;
    public string KindLabel => Entry.KindLabel;
    public string OsLabel => Entry.OsLabel;
    public string Collected => Entry.Collected?.ToString("yyyy-MM-dd") ?? "";
    public string Size => Entry.SizeBytes is long b ? FormatSize(b) : "";
    public string Note => Entry.Note;
    public bool CanSelect => Entry.CanRun;

    private bool _isSelected;
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (!CanSelect) value = false;
            if (SetField(ref _isSelected, value)) { OnPropertyChanged(nameof(ActionLabel)); _selectionChanged(); }
        }
    }

    /// <summary>What a run will do with this row (empty when not ticked).</summary>
    public string ActionLabel => IsSelected ? Entry.ActionLabel : "";

    // ── Job state while a run is going ───────────────────────────────
    private JobState? _job;
    public JobState? Job
    {
        get => _job;
        private set
        {
            if (SetField(ref _job, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                OnPropertyChanged(nameof(StatusLabel));
                OnPropertyChanged(nameof(StatusKind));
            }
        }
    }

    private string _jobMessage = "";
    public string JobMessage => _jobMessage;
    private double? _fraction;
    public double? Fraction { get => _fraction; private set { SetField(ref _fraction, value); OnPropertyChanged(nameof(HasFraction)); } }
    public bool HasFraction => IsBusy && Fraction.HasValue;

    public bool IsBusy => Job is JobState.Queued or JobState.Extracting or JobState.Analysing;

    /// <summary>The scanned status, or the job's state while a run is going.</summary>
    public string StatusLabel => Job switch
    {
        null => Entry.StatusLabel,
        JobState.Queued => "Queued",
        JobState.Extracting => _jobMessage.Length > 0 ? $"Extracting · {_jobMessage}" : "Extracting…",
        JobState.Analysing => Fraction.HasValue ? $"Analysing · {Fraction.Value:P0}" : "Analysing…",
        JobState.Done => "Done",
        JobState.Failed => "Failed: " + _jobMessage,
        _ => "Cancelled",
    };

    /// <summary>For the status colour: ok, busy, waiting, failed or plain.</summary>
    public string StatusKind => Job switch
    {
        JobState.Done => "ok",
        JobState.Failed or JobState.Cancelled => "failed",
        JobState.Queued or JobState.Extracting or JobState.Analysing => "busy",
        _ => Entry.Status switch
        {
            CollectionStatus.Analysed => "ok",
            CollectionStatus.WaitingForKape => "waiting",
            _ => "plain",
        },
    };

    public ICommand CancelCommand { get; }

    /// <summary>Back to the scanned status (before a new run).</summary>
    public void ResetJob()
    {
        _jobMessage = "";
        Fraction = null;
        Job = null;
    }

    public void Apply(JobUpdate u)
    {
        _jobMessage = u.Message;
        if (u.State != JobState.Analysing || u.Fraction == null) Fraction = null; else Fraction = u.Fraction;
        Job = u.State;
        OnPropertyChanged(nameof(StatusLabel));
    }

    public static string FormatSize(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):N1} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):N1} MB",
        >= 1L << 10 => $"{bytes / 1024.0:N0} KB",
        _ => $"{bytes} B",
    };
}
