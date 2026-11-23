using CsirtTriage.Core.Kape;
using CsirtTriage.Core.Uac;

// Headless runner: csirttriage --case <folder> [--name <case>] [--analyst <name>] [--uac-only | --kape-only]
string? Arg(string name)
{
    int i = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
bool Flag(string name) => args.Any(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

var caseFolder = Arg("--case");
if (caseFolder is null)
{
    Console.Error.WriteLine("Usage: csirttriage --case <folder> [--name <case>] [--analyst <name>] [--uac-only | --kape-only]");
    return 2;
}
caseFolder = Path.GetFullPath(caseFolder);
var caseName = Arg("--name") ?? Path.GetFileName(caseFolder);
var analyst = Arg("--analyst") ?? Environment.UserName;

try
{
    if (!Flag("--kape-only"))
    {
        var decompressDir = Path.Combine(caseFolder, "Decompressed");
        foreach (var uploadDir in new[] { "Upload", "Uploads" }.Select(d => Path.Combine(caseFolder, d)).Where(Directory.Exists))
            foreach (var archive in UacExtractor.ArchivePatterns.SelectMany(p => Directory.GetFiles(uploadDir, p)))
            {
                var name = UacExtractor.CollectionName(archive);
                if (UacExtractor.IsExtracted(decompressDir, name)) continue;
                try
                {
                    Directory.CreateDirectory(decompressDir);
                    UacExtractor.Extract(archive, decompressDir);
                    Console.WriteLine($"Extracted {name}");
                }
                catch (Exception ex) { Console.WriteLine($"[ERROR] {Path.GetFileName(archive)}: {ex.Message}"); }
            }

        var uac = new ParserConfig { CaseFolderPath = caseFolder, CaseName = caseName, AnalystName = analyst };
        new ParserOrchestrator(uac, Console.WriteLine).RunAll(CancellationToken.None);
    }

    if (!Flag("--uac-only"))
    {
        var kape = new AnalyserConfig { CaseFolderPath = caseFolder, CaseName = caseName, AnalystName = analyst };
        new AnalysisEngine(kape, Console.WriteLine).RunAll(CancellationToken.None);
    }
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ERROR] {ex}");
    return 1;
}
