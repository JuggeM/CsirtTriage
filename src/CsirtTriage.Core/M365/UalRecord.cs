using System.Globalization;
using System.Net;
using System.Text.Json;

namespace CsirtTriage.Core.M365;

/// <summary>
/// One unified audit log record from a Purview audit search export. Both
/// layouts are read: the current one (RecordId, CreationDate, RecordType,
/// Operation, UserId, AuditData, …) and the classic one (CreationDate,
/// UserIds, Operations, AuditData). Everything comes from the AuditData JSON
/// where it is there; the CSV columns are the fallback.
/// </summary>
public sealed class UalRecord
{
    public DateTime? TimeUtc { get; init; }
    public string Operation { get; init; } = "";
    public string Workload { get; init; } = "";
    public string User { get; init; } = "";
    /// <summary>Client IP without port or brackets; empty when the record has none.</summary>
    public string ClientIp { get; init; } = "";
    public string ResultStatus { get; init; } = "";
    public string UserAgent { get; private set; } = "";
    public string ObjectId { get; init; } = "";
    /// <summary>Exchange cmdlet parameters (Parameters) and OWA/mailbox properties (OperationProperties), by name.</summary>
    public Dictionary<string, string> Parameters { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Entra ID ModifiedProperties: name → (old, new).</summary>
    public Dictionary<string, (string Old, string New)> Modified { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Entra ID ExtendedProperties by name (UserAgent, RequestType, ResultStatusDetail, …).</summary>
    public Dictionary<string, string> Extended { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Entra ID Target entries (display names, IDs).</summary>
    public List<string> Targets { get; } = new();
    public string ErrorCode { get; init; } = "";
    public int OperationCount { get; init; } = 1;
    public string OrganizationName { get; init; } = "";
    /// <summary>The raw AuditData JSON.</summary>
    public string Raw { get; init; } = "";
    public string File { get; init; } = "";

    public bool Succeeded => !ResultStatus.Equals("Failed", StringComparison.OrdinalIgnoreCase)
                             && !ResultStatus.Equals("False", StringComparison.OrdinalIgnoreCase);

    public string Param(string name) => Parameters.TryGetValue(name, out var v) ? v : "";

    // ── Reading ──────────────────────────────────────────────────────
    /// <summary>Every record in a Purview export CSV. Rows without readable AuditData still yield a record from the columns.</summary>
    public static IEnumerable<UalRecord> ReadCsv(string path, Action<string>? warn = null)
    {
        using var csv = new CsvReader(path);
        int auditCol = csv.Col("AuditData");
        if (auditCol < 0)
        {
            warn?.Invoke($"[WARN] {System.IO.Path.GetFileName(path)}: no AuditData column — not a Purview audit export, skipped.");
            yield break;
        }
        int timeCol = csv.Col("CreationDate", "CreationTime");
        int opCol = csv.Col("Operation", "Operations");
        int userCol = csv.Col("UserId", "UserIds");
        int bad = 0;
        while (csv.Read())
        {
            UalRecord? r = null;
            try { r = Parse(csv[auditCol], csv[timeCol], csv[opCol], csv[userCol], path); }
            catch (JsonException) { bad++; }
            if (r != null) yield return r;
        }
        if (bad > 0) warn?.Invoke($"[WARN] {System.IO.Path.GetFileName(path)}: {bad} row(s) with unreadable AuditData skipped.");
    }

    public static UalRecord Parse(string auditData, string csvTime, string csvOperation, string csvUser, string file = "")
    {
        using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(auditData) ? "{}" : auditData);
        var j = doc.RootElement;
        string S(string name) => j.TryGetProperty(name, out var e) ? e.ValueKind switch
        {
            JsonValueKind.String => e.GetString() ?? "",
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => e.ToString(),
            _ => "",
        } : "";

        var r = new UalRecord
        {
            TimeUtc = ParseTime(S("CreationTime")) ?? ParseTime(csvTime),
            Operation = FirstNonEmpty(S("Operation"), csvOperation).Trim(),
            Workload = S("Workload"),
            User = FirstNonEmpty(S("UserId"), csvUser).Trim(),
            ClientIp = CleanIp(FirstNonEmpty(S("ClientIP"), S("ClientIPAddress"), S("ActorIpAddress"), S("ClientIp"))),
            ResultStatus = S("ResultStatus"),
            ObjectId = S("ObjectId"),
            ErrorCode = FirstNonEmpty(S("ErrorNumber"), S("LogonError")),
            OperationCount = int.TryParse(S("OperationCount"), out var n) && n > 0 ? n : 1,
            OrganizationName = S("OrganizationName"),
            UserAgent = S("UserAgent"),
            Raw = auditData,
            File = file,
        };
        AddNameValues(j, "Parameters", r.Parameters);
        AddNameValues(j, "OperationProperties", r.Parameters);
        AddNameValues(j, "ExtendedProperties", r.Extended);
        if (j.TryGetProperty("ModifiedProperties", out var mp) && mp.ValueKind == JsonValueKind.Array)
            foreach (var p in mp.EnumerateArray())
                if (p.ValueKind == JsonValueKind.Object && p.TryGetProperty("Name", out var nm) && nm.ValueKind == JsonValueKind.String && nm.GetString() is { Length: > 0 } name)
                    r.Modified[name] = (Str(p, "OldValue"), Str(p, "NewValue"));
        if (j.TryGetProperty("Target", out var tg) && tg.ValueKind == JsonValueKind.Array)
            foreach (var t in tg.EnumerateArray())
                if (t.ValueKind == JsonValueKind.Object && Str(t, "ID") is { Length: > 0 } id) r.Targets.Add(id);

        // Sign-in user agent lives in ExtendedProperties
        if (r.UserAgent.Length == 0 && r.Extended.TryGetValue("UserAgent", out var ua)) r.UserAgent = ua;
        return r;
    }

    private static void AddNameValues(JsonElement j, string property, Dictionary<string, string> into)
    {
        if (!j.TryGetProperty(property, out var arr)) return;
        // Always a list in Purview exports; a lone object is accepted too
        var items = arr.ValueKind == JsonValueKind.Array ? arr.EnumerateArray().ToList()
                  : arr.ValueKind == JsonValueKind.Object ? new List<JsonElement> { arr } : new List<JsonElement>();
        foreach (var p in items)
            if (p.ValueKind == JsonValueKind.Object && Str(p, "Name") is { Length: > 0 } name)
                into[name] = Str(p, "Value");
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? "" : v.ToString() : "";

    private static string FirstNonEmpty(params string[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";

    /// <summary>"203.0.113.45:51234", "[2001:db8::1]:443" and "::ffff:203.0.113.45" → the bare address.</summary>
    public static string CleanIp(string s)
    {
        s = (s ?? "").Trim();
        if (s.Length == 0) return "";
        if (s.StartsWith('['))
        {
            int end = s.IndexOf(']');
            s = end > 0 ? s[1..end] : s.Trim('[', ']');
        }
        else if (s.Count(c => c == ':') == 1) s = s[..s.IndexOf(':')];   // IPv4:port
        if (!IPAddress.TryParse(s, out var ip)) return "";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }

    private static readonly string[] TimeFormats =
    {
        "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-ddTHH:mm:ss.FFFFFFF", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-ddTHH:mm:ss.FFFFFFFZ",
        "yyyy-MM-dd HH:mm:ss", "M/d/yyyy h:mm:ss tt", "M/d/yyyy H:mm:ss", "d/M/yyyy H:mm:ss", "dd.MM.yyyy HH:mm:ss",
    };

    /// <summary>UAL times are UTC (AuditData.CreationTime has no zone; the CSV column may have Z).</summary>
    public static DateTime? ParseTime(string s)
    {
        s = (s ?? "").Trim();
        if (s.Length == 0) return null;
        return DateTime.TryParseExact(s, TimeFormats, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;
    }
}
