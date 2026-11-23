using CsirtTriage.Core.Case;

namespace CsirtTriage.Core;

/// <summary>
/// The headless run, shared by the CLI (csirttriage) and CsirtTriage.exe --case …:
///   --case &lt;folder&gt; [--name &lt;case&gt;] [--analyst &lt;name&gt;] [--list]
///   [--parallel &lt;n&gt;] [--only &lt;name,name,…&gt;] [--reanalyse] [--uac-only | --kape-only | --m365-only] [--no-ioc-search]
/// Exit codes: 0 ok, 1 error, 2 usage, 3 some collections failed, 130 cancelled.
/// </summary>
public static class Headless
{
    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter err, CancellationToken ct = default)
    {
        string? Arg(string name)
        {
            int i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }
        bool Flag(string name) => args.Any(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

        var caseFolder = Arg("--case");
        if (caseFolder is null)
        {
            err.WriteLine("""
                Usage: csirttriage --case <folder> [options]
                  --name <case>         case name (default: folder name)
                  --analyst <name>      analyst (default: user name)
                  --list                list the collections found and exit
                  --parallel <n>        collections analysed at the same time (default: half the cores, max 4)
                  --only <a,b,…>        only these collections (names as --list shows them)
                  --reanalyse           also run collections that are already analysed
                  --uac-only            only UAC collections
                  --kape-only           only KAPE collections
                  --m365-only           only Microsoft 365 collections
                  --no-ioc-search       skip the case IOC search
                """);
            return 2;
        }
        caseFolder = Path.GetFullPath(caseFolder);
        var settings = new TriageSettings
        {
            CaseFolder = caseFolder,
            CaseName = Arg("--name") ?? Path.GetFileName(caseFolder),
            Analyst = Arg("--analyst") ?? Environment.UserName,
            SearchIocs = !Flag("--no-ioc-search"),
        };
        if (int.TryParse(Arg("--parallel"), out var parallel)) settings.MaxParallel = parallel;

        var all = CollectionScanner.Scan(caseFolder, measureSizes: Flag("--list"));
        if (Flag("--list"))
        {
            output.WriteLine($"{"Collection",-40} {"Host",-10} {"Type",-5} {"Collected",-11} {"Size",9}  {"Status",-24} Action");
            foreach (var e in all)
                output.WriteLine($"{e.Name,-40} {e.Host,-10} {e.KindLabel,-5} {e.Collected?.ToString("yyyy-MM-dd") ?? "",-11} " +
                                  $"{(e.SizeBytes.HasValue ? $"{e.SizeBytes.Value / 1048576.0:N1} MB" : ""),9}  {e.StatusLabel,-24} {e.ActionLabel}" +
                                  (e.Note.Length > 0 ? $"   ({e.Note})" : ""));
            return 0;
        }

        var only = Arg("--only")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var selected = all.Where(e =>
                (only == null ? e.SelectedByDefault || Flag("--reanalyse") && e.CanRun
                              : only.Contains(e.Name, StringComparer.OrdinalIgnoreCase) && e.CanRun)
                && !(Flag("--uac-only") && e.Kind != CollectionKind.Uac)
                && !(Flag("--kape-only") && e.Kind != CollectionKind.Kape)
        && !(Flag("--m365-only") && e.Kind != CollectionKind.M365))
            .ToList();
        foreach (var e in all.Where(e => e.Status == CollectionStatus.WaitingForKape))
            output.WriteLine($"[WARN] {e.Name}: {e.Note}");

        var gate = new object();
        var runner = new CaseRunner(settings, (c, m) => { lock (gate) output.WriteLine(c != null && !m.Contains($"[{c}]", StringComparison.OrdinalIgnoreCase) ? $"[{c}] {m}" : m); });
        try
        {
            var result = await runner.RunAsync(selected, null, ct);
            return result.Failed > 0 ? 3 : 0;   // 3: some collections failed (see the log)
        }
        catch (OperationCanceledException)
        {
            err.WriteLine("Cancelled.");
            return 130;
        }
        catch (Exception ex)
        {
            err.WriteLine($"[ERROR] {ex}");
            return 1;
        }
    }
}
