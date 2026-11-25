namespace CsirtTriage.Core.M365;

/// <summary>
/// One row of an Entra ID sign-in log CSV export (Entra admin center → Sign-in
/// logs → Download → CSV). The download is one file per tab:
/// InteractiveSignIns_*.csv, NonInteractiveSignIns_*.csv (and
/// ApplicationSignIns / MSISignIns, AuthDetails). Columns are found by name,
/// with the alternatives the portal has used, so a column that is missing or
/// renamed leaves its field empty instead of failing the file.
/// </summary>
public sealed class EntraSignIn
{
    public DateTime? TimeUtc { get; init; }
    public string User { get; init; } = "";
    public string Ip { get; init; } = "";
    /// <summary>"City, State, CC" as the portal writes it.</summary>
    public string Location { get; init; } = "";
    /// <summary>Two-letter country code from Location (last part), or the whole Location when it has no code.</summary>
    public string Country { get; init; } = "";
    public string Status { get; init; } = "";
    public string ErrorCode { get; init; } = "";
    public string FailureReason { get; init; } = "";
    public string ClientApp { get; init; } = "";
    public string UserAgent { get; init; } = "";
    public string Application { get; init; } = "";
    public string AuthRequirement { get; init; } = "";
    public string MfaResult { get; init; } = "";
    public string MfaMethod { get; init; } = "";
    public string ConditionalAccess { get; init; } = "";
    public string SessionId { get; init; } = "";
    public string Asn { get; init; } = "";
    public string Os { get; init; } = "";
    public string Browser { get; init; } = "";
    public string Managed { get; init; } = "";
    public string Compliant { get; init; } = "";
    public string RiskLevel { get; init; } = "";
    public bool Interactive { get; init; } = true;
    public string File { get; init; } = "";

    public bool Succeeded => Status.Equals("Success", StringComparison.OrdinalIgnoreCase) || ErrorCode == "0";
    public bool SingleFactor => AuthRequirement.Contains("Single", StringComparison.OrdinalIgnoreCase);

    // ── File type ────────────────────────────────────────────────────
    public enum FileKind { NotSignIn, SignIns, AuthDetails }

    /// <summary>Tells a sign-in export from a unified audit log export (and from the AuthDetails files) by its header.</summary>
    public static FileKind Detect(IReadOnlyList<string> header)
    {
        bool Has(string name) => header.Any(h => h.Trim().Equals(name, StringComparison.OrdinalIgnoreCase));
        if (Has("AuditData")) return FileKind.NotSignIn;
        bool date = Has("Date (UTC)") || Has("Date") || Has("createdDateTime");
        if (date && (Has("Authentication method") || Has("Authentication Method")) && !Has("IP address") && !Has("IP Address"))
            return FileKind.AuthDetails;
        if (date && (Has("IP address") || Has("IP Address") || Has("ipAddress")) && (Has("Status") || Has("Sign-in error code")))
            return FileKind.SignIns;
        return FileKind.NotSignIn;
    }

    // Column alternatives, first match wins
    private static readonly string[] CDate = { "Date (UTC)", "Date", "createdDateTime", "CreatedDateTime" };
    private static readonly string[] CUser = { "Username", "User principal name", "userPrincipalName", "User", "Sign-in identifier" };
    private static readonly string[] CIp = { "IP address", "IP Address", "ipAddress", "IP address (seen by resource)" };
    private static readonly string[] CLocation = { "Location", "location" };
    private static readonly string[] CStatus = { "Status", "status" };
    private static readonly string[] CError = { "Sign-in error code", "Error code", "errorCode" };
    private static readonly string[] CReason = { "Failure reason", "failureReason" };
    private static readonly string[] CClient = { "Client app", "Client App", "clientAppUsed" };
    private static readonly string[] CAgent = { "User agent", "User Agent", "userAgent" };
    private static readonly string[] CApp = { "Application", "App", "appDisplayName" };
    private static readonly string[] CAuthReq = { "Authentication requirement", "authenticationRequirement" };
    private static readonly string[] CMfaResult = { "Multifactor authentication result", "MFA result" };
    private static readonly string[] CMfaMethod = { "Multifactor authentication auth method", "MFA auth method" };
    private static readonly string[] CCa = { "Conditional Access", "Conditional access", "conditionalAccessStatus" };
    private static readonly string[] CSession = { "Session ID", "Session Id", "sessionId" };
    private static readonly string[] CAsn = { "Autonomous system number", "ASN", "autonomousSystemNumber" };
    private static readonly string[] COs = { "Operating System", "Operating system" };
    private static readonly string[] CBrowser = { "Browser" };
    private static readonly string[] CManaged = { "Managed" };
    private static readonly string[] CCompliant = { "Compliant" };
    private static readonly string[] CRisk = { "Risk level (aggregated)", "Aggregated risk level", "Risk level during sign-in", "Risk level" };

    /// <summary>Every sign-in in one export file (not AuthDetails). Non-interactive when the file name says so.</summary>
    public static IEnumerable<EntraSignIn> ReadCsv(string path)
    {
        using var csv = new CsvReader(path);
        var name = System.IO.Path.GetFileName(path);
        bool interactive = !name.Contains("NonInteractive", StringComparison.OrdinalIgnoreCase)
                           && !name.Contains("Non-Interactive", StringComparison.OrdinalIgnoreCase)
                           && !name.StartsWith("Application", StringComparison.OrdinalIgnoreCase)
                           && !name.StartsWith("MSI", StringComparison.OrdinalIgnoreCase);
        int Col(string[] names) => csv.Col(names);
        int date = Col(CDate), user = Col(CUser), ip = Col(CIp), loc = Col(CLocation), status = Col(CStatus), err = Col(CError),
            reason = Col(CReason), client = Col(CClient), agent = Col(CAgent), app = Col(CApp), req = Col(CAuthReq),
            mfaR = Col(CMfaResult), mfaM = Col(CMfaMethod), ca = Col(CCa), session = Col(CSession), asn = Col(CAsn),
            os = Col(COs), browser = Col(CBrowser), managed = Col(CManaged), compliant = Col(CCompliant), risk = Col(CRisk);

        while (csv.Read())
        {
            var location = csv[loc].Trim();
            var statusText = csv[status].Trim();
            yield return new EntraSignIn
            {
                TimeUtc = UalRecord.ParseTime(csv[date]),
                User = csv[user].Trim(),
                Ip = UalRecord.CleanIp(csv[ip]),
                Location = location,
                Country = CountryOf(location),
                Status = statusText,
                ErrorCode = csv[err].Trim(),
                FailureReason = csv[reason].Trim(),
                ClientApp = csv[client].Trim(),
                UserAgent = csv[agent].Trim(),
                Application = csv[app].Trim(),
                AuthRequirement = csv[req].Trim(),
                MfaResult = csv[mfaR].Trim(),
                MfaMethod = csv[mfaM].Trim(),
                ConditionalAccess = csv[ca].Trim(),
                SessionId = csv[session].Trim(),
                Asn = csv[asn].Trim(),
                Os = csv[os].Trim(),
                Browser = csv[browser].Trim(),
                Managed = csv[managed].Trim(),
                Compliant = csv[compliant].Trim(),
                RiskLevel = csv[risk].Trim(),
                Interactive = interactive,
                File = path,
            };
        }
    }

    /// <summary>"Stockholm, Stockholm, SE" → "SE"; a location without a two-letter code is used as it is.</summary>
    public static string CountryOf(string location)
    {
        if (string.IsNullOrWhiteSpace(location)) return "";
        var last = location.Split(',').Last().Trim();
        return last.Length == 2 && last.All(char.IsLetter) ? last.ToUpperInvariant() : location.Trim();
    }
}
