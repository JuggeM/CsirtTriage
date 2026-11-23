using System.Text;

namespace CsirtTriage.Core.Case;

public enum CollectionKind { Uac, Kape }

/// <summary>
/// What the case-wide steps need to know about one analysed collection,
/// stored as host.txt in Level2\&lt;collection&gt;\ (key=value lines).
/// </summary>
/// <param name="SourceRoot">KAPE: the host's module output folder. UAC: the extracted collection root.</param>
/// <param name="ProcessedDir">UAC: Processed\&lt;collection&gt; (normalised CSVs). KAPE: empty.</param>
public sealed record CollectionInfo(string Hostname, string Collection, CollectionKind Kind,
                                    string SourceRoot, string ProcessedDir, IReadOnlyCollection<string> Ips)
{
    public const string FileName = "host.txt";

    public string KindLabel => Kind == CollectionKind.Uac ? "UAC" : "KAPE";

    public void Write(string resultsDir)
    {
        var sb = new StringBuilder();
        sb.Append("Hostname=").Append(Hostname).Append('\n')
          .Append("Collection=").Append(Collection).Append('\n')
          .Append("Kind=").Append(KindLabel).Append('\n')
          .Append("SourceRoot=").Append(SourceRoot).Append('\n')
          .Append("ProcessedDir=").Append(ProcessedDir).Append('\n')
          .Append("IPs=").Append(string.Join(",", Ips)).Append('\n');
        File.WriteAllText(Path.Combine(resultsDir, FileName), sb.ToString(), new UTF8Encoding(false));
    }

    public static CollectionInfo? Read(string resultsDir)
    {
        var path = Path.Combine(resultsDir, FileName);
        if (!File.Exists(path)) return null;
        var kv = File.ReadAllLines(path).Select(l => l.Split('=', 2)).Where(p => p.Length == 2)
            .GroupBy(p => p[0]).ToDictionary(g => g.Key, g => g.First()[1]);
        var collection = kv.GetValueOrDefault("Collection", Path.GetFileName(resultsDir));
        var host = kv.GetValueOrDefault("Hostname", "");
        return new CollectionInfo(
            host.Length > 0 ? host : collection,
            collection,
            kv.GetValueOrDefault("Kind", "KAPE").Equals("UAC", StringComparison.OrdinalIgnoreCase) ? CollectionKind.Uac : CollectionKind.Kape,
            kv.GetValueOrDefault("SourceRoot", ""),
            kv.GetValueOrDefault("ProcessedDir", ""),
            kv.GetValueOrDefault("IPs", "").Split(',', StringSplitOptions.RemoveEmptyEntries));
    }
}
