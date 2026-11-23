namespace CsirtTriage.Core.M365;

/// <summary>What the Microsoft 365 unified audit log analysis looks at, and its thresholds.</summary>
public class M365Config
{
    public bool AnalyseSignIns { get; set; } = true;
    public bool AnalyseMailbox { get; set; } = true;
    public bool AnalyseDirectory { get; set; } = true;
    public bool AnalyseFiles { get; set; } = true;
    public bool AnalyseMailAccess { get; set; } = true;

    /// <summary>Failed sign-ins from one IP to one account before it counts as brute force.</summary>
    public int BruteForceThreshold { get; set; } = 10;
    /// <summary>Accounts with failed sign-ins from one IP before it counts as password spray.</summary>
    public int SprayAccounts { get; set; } = 5;
    /// <summary>Distinct IPs one account signs in from within 24 hours before it is flagged.</summary>
    public int IpsPerUserPerDay { get; set; } = 5;
    /// <summary>Files one account downloads within an hour before it counts as mass download.</summary>
    public int DownloadsPerHour { get; set; } = 100;
    /// <summary>Mail items one account accesses within an hour (MailItemsAccessed) before it is flagged.</summary>
    public int MailItemsPerHour { get; set; } = 500;
}
