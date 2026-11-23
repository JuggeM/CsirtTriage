using System.Text;

namespace CsirtTriage.Core.Case;

public enum CollectionKind { Uac, Kape, M365 }

/// <summary>
/// What the case-wide steps need to know about one analysed collection,
/// stored as host.txt in Level2\&lt;collection&gt;\ (key=value lines).
/// </summary>
/// <param name="SourceRoot">KAPE: the host's module output folder. UAC: the extracted collection root. M365: the folder with the audit log CSVs.</param>
/// <param name="ProcessedDir">UAC and M365: Processed\&lt;collection&gt; (normalised CSVs). KAPE: empty.</param>
public sealed record CollectionInfo(string Hostname, string Collection, CollectionKind Kind,
                                    string SourceRoot, string ProcessedDir, IReadOnlyCollection<string> Ips)
{
    public const string FileName = "host.txt";

    public string KindLabel => Kind switch { CollectionKind.Uac => "UAC", CollectionKind.M365 => "M365", _ => "KAPE" };

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
            kv.GetValueOrDefault("Kind", "KAPE").ToUpperInvariant() switch { "UAC" => CollectionKind.Uac, "M365" => CollectionKind.M365, _ => CollectionKind.Kape },
            kv.GetValueOrDefault("SourceRoot", ""),
            kv.GetValueOrDefault("ProcessedDir", ""),
            kv.GetValueOrDefault("IPs", "").Split(',', StringSplitOptions.RemoveEmptyEntries));
    }
}
