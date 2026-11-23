using CsirtTriage.Core.Case;

// Headless runner, same scan and runner as the app:
//   csirttriage --case <folder> [--name <case>] [--analyst <name>] [--list]
//               [--parallel <n>] [--only <name,name,…>] [--reanalyse] [--uac-only | --kape-only] [--no-ioc-search]
string? Arg(string name)
{
    int i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
bool Flag(string name) => args.Any(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

var caseFolder = Arg("--case");
if (caseFolder is null)
{
    Console.Error.WriteLine("""
        Usage: csirttriage --case <folder> [options]
          --name <case>         case name (default: folder name)
          --analyst <name>      analyst (default: user name)
          --list                list the collections found and exit
          --parallel <n>        collections analysed at the same time (default: half the cores, max 4)
          --only <a,b,…>        only these collections (names as --list shows them)
          --reanalyse           also run collections that are already analysed
          --uac-only            only UAC collections
          --kape-only           only KAPE collections
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
    Console.WriteLine($"{"Collection",-40} {"Host",-10} {"Type",-5} {"Collected",-11} {"Size",9}  {"Status",-24} Action");
    foreach (var e in all)
        Console.WriteLine($"{e.Name,-40} {e.Host,-10} {e.KindLabel,-5} {e.Collected?.ToString("yyyy-MM-dd") ?? "",-11} " +
                          $"{(e.SizeBytes.HasValue ? $"{e.SizeBytes.Value / 1048576.0:N1} MB" : ""),9}  {e.StatusLabel,-24} {e.ActionLabel}" +
                          (e.Note.Length > 0 ? $"   ({e.Note})" : ""));
    return 0;
}

var only = Arg("--only")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var selected = all.Where(e =>
        (only == null ? e.SelectedByDefault || Flag("--reanalyse") && e.CanRun
                      : only.Contains(e.Name, StringComparer.OrdinalIgnoreCase) && e.CanRun)
        && !(Flag("--uac-only") && e.Kind != CollectionKind.Uac)
        && !(Flag("--kape-only") && e.Kind != CollectionKind.Kape))
    .ToList();
foreach (var e in all.Where(e => e.Status == CollectionStatus.WaitingForKape))
    Console.WriteLine($"[WARN] {e.Name}: {e.Note}");

var runner = new CaseRunner(settings, (_, m) => Console.WriteLine(m));
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, a) => { a.Cancel = true; cts.Cancel(); };
try
{
    var result = await runner.RunAsync(selected, null, cts.Token);
    return result.Failed > 0 ? 3 : 0;   // 3: some collections failed (see the log)
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Cancelled.");
    return 130;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ERROR] {ex}");
    return 1;
}
