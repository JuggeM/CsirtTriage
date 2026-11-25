using System.Diagnostics;
using System.Globalization;
using System.Text;
using CsirtTriage.Core.Case;
using CsirtTriage.Core.Kape;
using CsirtTriage.Core.Reporting;

namespace CsirtTriage.Core.M365;

/// <summary>
/// Analyses one Microsoft 365 collection: the Purview audit search CSV
/// export(s) in one folder (Uploads\M365, or one subfolder of it per export).
/// Normalised rows go to Processed\&lt;collection&gt;\Normalized_UAL.csv, the
/// analysis to Level2\&lt;collection&gt; in the same files as every other
/// collection, so the case-wide steps treat the tenant like another host.
/// </summary>
public sealed class M365Engine
{
    public const string ProcessedMarkerFile = ".processed";
    public const string NormalizedFile = "Normalized_UAL.csv";
    public const string NormalizedSignInFile = "Normalized_ENTRA.csv";

    private readonly TriageSettings _settings;
    private readonly Action<string> _log;

    public M365Engine(TriageSettings settings, Action<string> log)
    {
        _settings = settings;
        _log = log;
    }

    /// <summary>The modules shown in the QuickWins coverage table.</summary>
    private IReadOnlyList<(string Source, string Module, bool Enabled)> Modules => new[]
    {
        (UalAnalyser.SignIn, "UserLoggedIn / UserLoginFailed", _settings.M365.AnalyseSignIns),
        (UalAnalyser.Mailbox, "Exchange admin and mailbox operations", _settings.M365.AnalyseMailbox),
        (UalAnalyser.Directory, "Entra ID directory operations", _settings.M365.AnalyseDirectory),
        (UalAnalyser.Files, "SharePoint / OneDrive", _settings.M365.AnalyseFiles),
        (UalAnalyser.MailAccess, "MailItemsAccessed", _settings.M365.AnalyseMailAccess),
        (EntraSignInAnalyser.Source, "Entra ID sign-in log export (interactive, non-interactive)", _settings.M365.AnalyseEntraSignIns),
    };

    /// <summary>Which report section a record belongs to (also used for the coverage table).</summary>
    public static string SourceOf(UalRecord r) =>
        r.Operation is "UserLoggedIn" or "UserLoginFailed" ? UalAnalyser.SignIn
        : r.Operation == "MailItemsAccessed" ? UalAnalyser.MailAccess
        : r.Workload is "SharePoint" or "OneDrive" ? UalAnalyser.Files
        : r.Workload is "Exchange" || r.Operation.Contains('-') ? UalAnalyser.Mailbox
        : r.Workload is "AzureActiveDirectory" || r.Operation.EndsWith('.') ? UalAnalyser.Directory
        : "M365-OTHER";

    public static IEnumerable<string> CsvFiles(string folder) =>
        Directory.Exists(folder)
            ? Directory.EnumerateFiles(folder, "*.csv", new EnumerationOptions { RecurseSubdirectories = false, IgnoreInaccessible = true })
                       .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            : Enumerable.Empty<string>();

    public void AnalyseCollection(string name, string folder, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var outDir = Path.Combine(_settings.ResultsRoot, name);
        var processedDir = Path.Combine(_settings.CaseFolder, CollectionScanner.ProcessedFolder, name);
        foreach (var dir in new[] { outDir, processedDir })
            if (Directory.Exists(dir) && Directory.EnumerateFileSystemEntries(dir).Any())
            {
                _log($"[{name}] Replacing earlier output in {dir}");
                Directory.Delete(dir, recursive: true);
            }
        Directory.CreateDirectory(outDir);
        Directory.CreateDirectory(processedDir);
        _log($"===== M365 collection: {name} =====");

        var rules = M365Rules.Load(_settings.Kape.ResolveRulesPath(), _log);
        var ctx = new AnalysisContext(_settings.Kape, folder, _log, ct);
        var analyser = new UalAnalyser(_settings.M365, rules, ctx);
        var signIns = new EntraSignInAnalyser(_settings.M365, rules, ctx);
        StreamWriter? signInNorm = null;
        long signInRows = 0;
        var domains = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        long rows = 0;

        using (var norm = new StreamWriter(Path.Combine(processedDir, NormalizedFile), false, new UTF8Encoding(false)))
        {
            norm.WriteLine("Timestamp,Hostname,LogType,Daemon,User,IP,Message,Severity,Raw");
            foreach (var file in CsvFiles(folder))
            {
                // Unified audit log and Entra sign-in exports sit in the same folder; the header tells them apart
                EntraSignIn.FileKind kind;
                using (var probe = new CsvReader(file)) kind = EntraSignIn.Detect(probe.Header);
                if (kind == EntraSignIn.FileKind.AuthDetails)
                {
                    _log($"[{name}] {Path.GetFileName(file)}: Entra authentication details — not used (the sign-in files hold what is needed).");
                    continue;
                }
                if (kind == EntraSignIn.FileKind.SignIns)
                {
                    if (!_settings.M365.AnalyseEntraSignIns) { _log($"[{name}] {Path.GetFileName(file)}: Entra sign-ins switched off in Sources — skipped."); continue; }
                    signInNorm ??= NewNormalized(Path.Combine(processedDir, NormalizedSignInFile));
                    long n = 0;
                    foreach (var s in EntraSignIn.ReadCsv(file))
                    {
                        if ((++n & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
                        var cov = ctx.CoverageFor(EntraSignInAnalyser.Source);
                        cov.Rows++;
                        cov.See(s.TimeUtc);
                        if (!cov.Files.Contains(Path.GetFileName(file))) cov.Files.Add(Path.GetFileName(file));
                        if (s.User.LastIndexOf('@') is int sat and >= 0)
                        {
                            var d = s.User[(sat + 1)..];
                            domains[d] = domains.GetValueOrDefault(d) + 1;
                        }
                        signInNorm.WriteLine(Csv.Row(
                            s.TimeUtc?.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) ?? "",
                            "", "ENTRA", s.Application, s.User, s.Ip,
                            $"{(s.Interactive ? "Interactive" : "Non-interactive")} sign-in | {s.Status}{(s.ErrorCode is "" or "0" ? "" : $" {s.ErrorCode} {s.FailureReason}")} | {s.Location} | {s.ClientApp} | {s.AuthRequirement}",
                            s.Succeeded ? "Info" : "Failed",
                            $"ASN={s.Asn}; Session={s.SessionId}; UA={s.UserAgent}; MFA={s.MfaResult} {s.MfaMethod}; CA={s.ConditionalAccess}; OS={s.Os}; Browser={s.Browser}"));
                        signIns.See(s);
                    }
                    signInRows += n;
                    _log($"[{name}] {Path.GetFileName(file)}: {n:N0} Entra sign-in(s)");
                    continue;
                }

                _log($"[{name}] Reading {Path.GetFileName(file)}");
                long before = rows;
                foreach (var r in UalRecord.ReadCsv(file, _log))
                {
                    if ((++rows & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
                    var source = SourceOf(r);
                    var cov = ctx.CoverageFor(source);
                    cov.Rows++;
                    cov.See(r.TimeUtc);
                    if (!cov.Files.Contains(Path.GetFileName(file))) cov.Files.Add(Path.GetFileName(file));
                    if (r.User.LastIndexOf('@') is int at and >= 0)
                    {
                        var d = r.User[(at + 1)..];
                        domains[d] = domains.GetValueOrDefault(d) + 1;
                    }
                    norm.WriteLine(Csv.Row(
                        r.TimeUtc?.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) ?? "",
                        "", "UAL", r.Workload, r.User, r.ClientIp, Message(r), r.Succeeded ? "Info" : "Failed", r.Raw));
                    analyser.See(r);
                }
                _log($"[{name}] {Path.GetFileName(file)}: {rows - before:N0} record(s)");
            }
        }
        signInNorm?.Dispose();
        if (rows == 0 && signInRows == 0)
            _log($"[WARN] [{name}] No audit records or sign-ins found in {folder} (expected Purview audit search or Entra sign-in CSV exports).");
        analyser.Complete();
        signIns.Complete();

        // The tenant's name: its most used mail domain, a custom domain before *.onmicrosoft.com
        var tenant = domains.OrderBy(kv => kv.Key.EndsWith(".onmicrosoft.com", StringComparison.OrdinalIgnoreCase))
                            .ThenByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault() ?? name;
        _log($"[{name}] Tenant: {tenant}, {rows:N0} audit record(s), {signInRows:N0} sign-in(s)");

        HostReport.Write(outDir, new CollectionInfo(tenant, name, CollectionKind.M365, folder, processedDir, Array.Empty<string>()),
            ctx, Modules, _settings.CaseName, _settings.Analyst);
        int crit = ctx.Findings.Count(f => f.Severity == Severity.Critical), high = ctx.Findings.Count(f => f.Severity == Severity.High);
        _log($"[{name}] {ctx.Findings.Count} finding(s): {crit} critical, {high} high — {sw.Elapsed:mm\\:ss}");
        try { QuickWinsRtf.Convert(outDir); }
        catch (Exception ex) { _log($"[WARN] [{name}] RTF conversion failed: {ex.Message}"); }
        File.WriteAllText(Path.Combine(outDir, ProcessedMarkerFile), $"Processed {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z{Environment.NewLine}");
    }

    private static StreamWriter NewNormalized(string path)
    {
        var w = new StreamWriter(path, false, new UTF8Encoding(false));
        w.WriteLine("Timestamp,Hostname,LogType,Daemon,User,IP,Message,Severity,Raw");
        return w;
    }

    /// <summary>One readable line per record for the normalised CSV: operation and its main parameters.</summary>
    private static string Message(UalRecord r)
    {
        var parts = new List<string> { r.Operation };
        if (r.ObjectId.Length > 0 && r.ObjectId.Length < 200) parts.Add(r.ObjectId);
        if (r.Parameters.Count > 0) parts.Add(string.Join("; ", r.Parameters.Take(8).Select(kv => $"{kv.Key}={kv.Value}")));
        if (r.ErrorCode.Length > 0 && !r.Succeeded) parts.Add($"error {r.ErrorCode}");
        var s = string.Join(" | ", parts);
        return s.Length > 500 ? s[..499] + "…" : s;
    }
}
