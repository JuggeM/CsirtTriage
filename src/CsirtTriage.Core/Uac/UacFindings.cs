using System.Globalization;
using System.Text.RegularExpressions;

namespace CsirtTriage.Core.Uac;

/// <summary>
/// Turns the UAC parsers' finding lines ("[AUTH] [HIGH] [2026-11-01 09:21:40 UTC] text")
/// into the shared <see cref="Finding"/> model, so UAC and KAPE collections
/// write the same Findings.csv and feed the same case summary and report.
/// </summary>
public static class UacFindings
{
    // "x3 [2026-11-01 09:15:22 → 2026-11-01 09:15:29 UTC]"
    private static readonly Regex CountSpanRx = new(
        @"\bx(?<n>\d+)\s*\[(?<a>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*(?:→|->)\s*(?<b>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?: UTC)?\]",
        RegexOptions.Compiled);
    // "(x14)" or "(x14, last 2026-11-01 09:15:29)"
    private static readonly Regex CountRx = new(
        @"\(x(?<n>\d+)(?:,\s*last (?<b>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))?\)", RegexOptions.Compiled);

    public static Finding From(string source, string raw)
    {
        var p = KeyFindingsBuilder.Parse(source, raw);
        int count = 1;
        DateTime? last = null;
        var m = CountSpanRx.Match(raw);
        if (m.Success)
        {
            count = int.Parse(m.Groups["n"].Value, CultureInfo.InvariantCulture);
            last = Time(m.Groups["b"].Value);
        }
        else if ((m = CountRx.Match(raw)).Success)
        {
            count = int.Parse(m.Groups["n"].Value, CultureInfo.InvariantCulture);
            if (m.Groups["b"].Success) last = Time(m.Groups["b"].Value);
        }

        return new Finding
        {
            Severity = p.Severity switch
            {
                "CRITICAL" => Severity.Critical,
                "HIGH" => Severity.High,
                "MEDIUM" => Severity.Medium,
                "SUSPICIOUS" => Severity.Suspicious,
                _ => Severity.Low,
            },
            TimeUtc = p.TimeUtc,
            LastUtc = last,
            Count = Math.Max(1, count),
            Source = p.Source,
            Text = p.Text,
        };
    }

    public static List<Finding> FromAll(IEnumerable<(string Source, string Finding)> all) =>
        all.Select(f => From(f.Source, f.Finding)).ToList();

    private static DateTime? Time(string s) =>
        DateTime.TryParseExact(s, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;
}
