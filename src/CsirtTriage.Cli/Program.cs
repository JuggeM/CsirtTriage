using CsirtTriage.Core.Kape;

// Headless runner: csirttriage --case <folder> [--name <case>] [--analyst <name>]
string? Arg(string name)
{
    int i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

var caseFolder = Arg("--case");
if (caseFolder is null)
{
    Console.Error.WriteLine("Usage: csirttriage --case <folder> [--name <case>] [--analyst <name>]");
    return 2;
}

var config = new AnalyserConfig
{
    CaseFolderPath = Path.GetFullPath(caseFolder),
    CaseName = Arg("--name") ?? Path.GetFileName(Path.GetFullPath(caseFolder)),
    AnalystName = Arg("--analyst") ?? Environment.UserName,
};
try
{
    new AnalysisEngine(config, Console.WriteLine).RunAll(CancellationToken.None);
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ERROR] {ex}");
    return 1;
}
