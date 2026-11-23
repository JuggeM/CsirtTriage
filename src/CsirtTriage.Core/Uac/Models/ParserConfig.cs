using System.Collections.ObjectModel;

namespace CsirtTriage.Core.Uac;

/// <summary>
/// All analyst-configurable settings.  Populated from the UI, passed
/// into the parser orchestration layer at run time.
/// </summary>
public class ParserConfig
{
    // ── Case ─────────────────────────────────────────────────────────
    public string CaseName { get; set; } = string.Empty;
    public string AnalystName { get; set; } = string.Empty;
    public string CaseFolderPath { get; set; } = string.Empty;
    public string OutputPath { get; set; } = "Level2";

    /// <summary>
    /// The folder analysis results are written to (Level2\ by default). A
    /// relative OutputPath is resolved against the case folder. The case root
    /// (evidence) and Processed\ (parsed data) are never used, so results
    /// never mix with their input; both fall back to &lt;case&gt;\Level2.
    /// </summary>
    public string ResolveOutputPath()
    {
        string caseDir = string.IsNullOrWhiteSpace(CaseFolderPath) ? string.Empty : Path.GetFullPath(CaseFolderPath);
        string defaultOut = Path.Combine(caseDir, "Level2");
        if (string.IsNullOrWhiteSpace(OutputPath)) return defaultOut;

        string resolved = Path.IsPathRooted(OutputPath)
            ? Path.GetFullPath(OutputPath)
            : Path.GetFullPath(Path.Combine(caseDir, OutputPath));

        static bool Same(string a, string b) =>
            string.Equals(a.TrimEnd('\\', '/'), b.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
        if (caseDir.Length > 0 && (Same(resolved, caseDir) || Same(resolved, Path.Combine(caseDir, "Processed"))))
            return defaultOut;
        return resolved;
    }

    // Optional date-range filter (null = no filter)
    public DateTime? FilterFrom { get; set; }
    public DateTime? FilterTo { get; set; }

    // ── Parser toggles ───────────────────────────────────────────────
    public bool ParseAuth { get; set; } = true;
    public bool ParseCrontab { get; set; } = true;
    public bool ParseMessages { get; set; } = true;
    public bool ParseSyslog { get; set; } = true;
    public bool ParseWebLogs { get; set; } = true;
    public bool ParseDocker { get; set; } = true;
    public bool ParseAudit { get; set; } = true;
    public bool ParseLiveResponse { get; set; } = true;
    public bool ParseBodyFile { get; set; } = true;
    public bool ParseJournal { get; set; } = true;
    public bool ParseBashHistory { get; set; } = true;
    public bool ParseZsh { get; set; } = true;
    public bool ParseVimInfo { get; set; } = true;
    public bool ParseDbHistory { get; set; } = true;
    public bool ParsePythonHistory { get; set; } = true;
    public bool ParseWgetHsts { get; set; } = true;
    public bool ParseLessHst { get; set; } = true;
    public bool ParseAiAgents { get; set; } = true;
    /// <summary>hash_executables.sha1: executables worth a hash lookup, scored by path and name.</summary>
    public bool ParseHashes { get; set; } = true;

    // ── Detection thresholds ─────────────────────────────────────────
    /// <summary>Failed login count before an IP is flagged as brute-force.</summary>
    public int BruteForceThreshold { get; set; } = 5;

    /// <summary>Requests-per-minute before a web IP is flagged.</summary>
    public int WebBruteForceRpm { get; set; } = 50;

    // ── Keyword lists ────────────────────────────────────────────────
    public ObservableCollection<string> Rank1Keywords { get; set; } = new(new[]
    {
        "reverse shell", "bash -i", "netcat", "execve=",
        "insmod", "modprobe", "chattr", "kernel panic",
        "segfault", "selinux denial", "failed root login"
    });

    public ObservableCollection<string> Rank2Keywords { get; set; } = new(new[]
    {
        "wget", "curl", "base64", "new user", "scp",
        "rsync", "unknown login", "potential backdoor"
    });

    public ObservableCollection<string> WhitelistPatterns { get; set; } = new(new[]
    {
        "/var/log/", "/opt/CrowdStrike/", "/usr/", "/lib"
    });

    // ── Body file ────────────────────────────────────────────────────
    public int BodyFileMinScore { get; set; } = 6;
    public int BodyFileRecencyDays { get; set; } = 30;
    public long BodyFileMinSizeBytes { get; set; } = 1024;
    public int BodyFileMaxFindingsFolder { get; set; } = 10;
    public bool BodyFileRequireKeyword { get; set; } = true;

    public ObservableCollection<string> BodyFileSuspiciousKeywords { get; set; } = new(new[]
    {
        "reverse_shell", "backdoor", "mimikatz", "c2", "creds", "payload", "dump",
        "chattr", "shadow", "netcat", "nc ", "/nc", "suid", "exploit", "ps1",
        "lateral", "exfil", "xmr", "xmrig", "crypto", "miner", "bash -i", "socat",
        "pkexec", "wget", "curl", "/bash -i"
    });

    public ObservableCollection<string> BodyFileWhitelistPrefixes { get; set; } = new(new[]
    {
        "/usr/", "/lib", "/etc/", "/proc/", "/sys/", "/boot/",
        "/var/log/", "/var/cache/", "/var/run/", "/opt/CrowdStrike/",
        "/tmp/CSIRT_Collection/"
    });

    // ── Output options ───────────────────────────────────────────────
    public bool OutputCollapseDups { get; set; } = true;
}