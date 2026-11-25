using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using Font = DocumentFormat.OpenXml.Spreadsheet.Font;

namespace CsirtTriage.Core.Reporting
{
    /// <summary>
    /// Findings as rows for the team's case tracker spreadsheet, one row per
    /// finding. Two sheets: "Hosts" (UAC and KAPE collections, in the tracker's
    /// own column order) and "M365" (the tenant, with account, source IP,
    /// location and target instead of host columns). Who, from where and to
    /// where are pulled from the finding text (best effort); Mitre Framework and
    /// ReportHeading are left for the analyst. Written as .xlsx so it opens and
    /// pastes the same in any Excel language.
    /// </summary>
    public static class CaseTracker
    {
        public const string FileName = "CaseTracker.xlsx";
        public const string HostsSheet = "Hosts";
        public const string M365Sheet = "M365";

        public static readonly string[] Columns =
        {
            "date/time", "DataSource", "hostsystem", "host IP Address", "Eventdescription", "Account", "SourceHost",
            "SourceIP", "Destination Host", "Remote URL", "Destination IP", "Mitre Framework", "Notes", "Analyst", "ReportHeading",
        };
        private static readonly double[] Widths = { 19, 22, 14, 16, 70, 18, 16, 15, 16, 30, 15, 18, 80, 14, 18 };

        public static readonly string[] M365Columns =
        {
            "date/time", "DataSource", "Tenant", "Account", "Source IP", "Location", "Eventdescription", "Target",
            "Mitre Framework", "Notes", "Analyst", "ReportHeading",
        };
        private static readonly double[] M365Widths = { 19, 22, 16, 26, 15, 26, 70, 30, 18, 80, 14, 18 };

        public sealed record Row(DateTime? Time, string[] Values);

        /// <summary>The rows for both sheets.</summary>
        public sealed record Tracker(List<Row> Hosts, List<Row> M365)
        {
            public int Count => Hosts.Count + M365.Count;
        }

        // M365 fields
        private static readonly Regex EmailRx = new(@"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b", RegexOptions.Compiled);
        private static readonly Regex QuotedRx = new(@"'(?<v>[^']{1,120})'", RegexOptions.Compiled);
        // "Amsterdam, Noord-Holland, NL" as the Entra sign-in log writes locations
        private static readonly Regex LocationRx = new(@"(?<![\w])(?<l>[A-Z][\p{L} .'-]{1,40}, [\p{L} .'-]{1,40}, [A-Z]{2})\b", RegexOptions.Compiled);

        // ── Field extraction ─────────────────────────────────────────────
        private const string Ip = @"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)";
        private static readonly Regex IpRx = new($@"(?<![\d.]){Ip}(?![\d.]*\d)", RegexOptions.Compiled);
        private static readonly Regex UrlRx = new(@"\b(?:https?|ftp)://[^\s'""|;)<>]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        // "from 203.0.113.45 (KALI)", "from external IP 203.0.113.45", "from WS01 (10.10.1.21)", "from KALI (203.0.113.45)"
        private static readonly Regex FromRx = new(
            $@"\bfrom\s+(?:external\s+(?:IP\s+)?)?(?:(?<h1>[A-Za-z][\w.-]*)\s+\()?(?<ip>{Ip})\)?(?:\s+\((?<h2>[A-Za-z][\w.-]*)\))?",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        // "Src: 203.0.113.45", "SourceIp=…", "client: …" (Sigma details), "…: 203.0.113.45 got 302" (web),
        // "Failed login: 203.0.113.45 user=root" (auth)
        private static readonly Regex SrcFieldRx = new(
            $@"\b(?:src|source(?:\s*ip)?|ipaddress|client(?:\s*ip)?)\s*[:=]\s*(?<ip>{Ip})|:\s+(?<ip>{Ip})\s+(?:got\s+\d{{3}}|users?=)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        // A host in "(…)" after the address has upper case, a digit or a dot; "(password)" / "(publickey)" is the auth method
        private static readonly Regex HostLikeRx = new(@"[A-Z0-9.]", RegexOptions.Compiled);
        private static readonly Regex CountRx = new(@"^x\d+$", RegexOptions.Compiled);
        // First segment of registry and file paths, not domains
        private static readonly HashSet<string> NotDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft", "Windows", "SOFTWARE", "SYSTEM", "Program", "Users", "ProgramData", "AppData", "Device", "Volume",
            "HKLM", "HKCU", "HKU", "Policies", "CurrentVersion", "Classes", "Services", "ControlSet001", "CurrentControlSet",
        };
        private static readonly Regex FromHostRx = new(@"\bfrom\s+(?<h>[A-Z][A-Z0-9-]{1,14})\b(?!\.)", RegexOptions.Compiled);
        private static readonly Regex UncRx = new(@"\\\\(?<h>[A-Za-z0-9][\w.-]*)\\", RegexOptions.Compiled);
        // DOMAIN\user (not path pieces like \Users\Public), user@domain, user=x, then "by/for/as x"
        private static readonly Regex[] AccountRx =
        {
            new(@"(?<![\\:\w.])(?<a>[A-Za-z][\w.-]{0,30}\\[\w.$-]+)(?![\\\w])", RegexOptions.Compiled),
            new(@"\bAccount (?:created|enabled|deleted|renamed)?:?\s*'?(?<a>[\w.$-]+)'?", RegexOptions.Compiled),
            new(@"\b(?<a>[\w.$-]+)\s+logged\s+(?:in|on)\b", RegexOptions.Compiled),
            new(@"\busers?\s+(?<a>[a-z_][\w.$-]*)(?=[,\s])", RegexOptions.Compiled),
            new(@"\b(?<a>[\w.-]+@[A-Za-z][\w-]*(?:\.[\w-]+)+)\b", RegexOptions.Compiled),
            new(@"\busers?[=:]\s*(?<a>[\w.$-]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new(@"\b(?:by|for|as)\s+(?<a>[A-Za-z][\w.$-]{1,40})(?=[\s,;)(]|$)", RegexOptions.Compiled),
        };
        private static readonly HashSet<string> NotAccounts = new(StringComparer.OrdinalIgnoreCase)
        {
            "external", "the", "an", "this", "that", "user", "users", "host", "unknown", "analyst", "default", "service", "services",
            "local", "remote", "all", "more", "same", "each", "every", "rule", "rules", "file", "files", "process", "example",
        };

        /// <summary>One tracker row per finding, oldest first: UAC and KAPE findings on the Hosts sheet, M365 findings on the M365 sheet.</summary>
        public static Tracker Rows(CaseReportData data, IEnumerable<ReportFinding> findings)
        {
            var list = findings.ToList();
            return new Tracker(
                HostRows(data, list.Where(f => !IsM365(f))),
                M365Rows(data, list.Where(IsM365)));
        }

        private static bool IsM365(ReportFinding f) => f.Kind.Equals("M365", StringComparison.OrdinalIgnoreCase);

        private static List<Row> HostRows(CaseReportData data, IEnumerable<ReportFinding> findings)
        {
            var ipOwner = data.Hosts.SelectMany(h => h.Ips.Select(ip => (ip, h.Host)))
                .GroupBy(x => x.ip).ToDictionary(g => g.Key, g => g.First().Host);
            var rows = new List<Row>();
            foreach (var f in findings.OrderBy(f => f.TimeUtc ?? DateTime.MaxValue).ThenBy(f => f.Host))
            {
                var (title, detail) = CaseReport.SplitTitle(f.Text);
                var all = f.Text;
                var hostIps = string.Join(", ", f.HostIps);

                string srcHost = "", srcIp = "", dstHost = "", dstIp = "";
                var from = FromRx.Match(all);
                if (from.Success)
                {
                    srcIp = from.Groups["ip"].Value;
                    srcHost = from.Groups["h1"].Success ? from.Groups["h1"].Value : from.Groups["h2"].Success ? from.Groups["h2"].Value : "";
                    // "(x4)" is a count and "(password)" the auth method, not a host
                    if (CountRx.IsMatch(srcHost) || NotAccounts.Contains(srcHost) || !HostLikeRx.IsMatch(srcHost)) srcHost = "";
                    if (srcHost.Length == 0 && ipOwner.TryGetValue(srcIp, out var known)) srcHost = known;
                    if (srcHost.Length == 0 && ipOwner.TryGetValue(srcIp, out var owner)) srcHost = owner;
                }
                else if (SrcFieldRx.Match(all) is { Success: true } sf)
                {
                    srcIp = sf.Groups["ip"].Value;
                    if (ipOwner.TryGetValue(srcIp, out var owner)) srcHost = owner;
                }
                else if (FromHostRx.Match(title) is { Success: true } fh && !NotAccounts.Contains(fh.Groups["h"].Value))
                    srcHost = fh.Groups["h"].Value;

                if (srcIp.Length > 0 || srcHost.Length > 0)
                {
                    // Inbound: the activity arrived at this host
                    dstHost = f.Host;
                    dstIp = hostIps;
                }
                else
                {
                    // Outbound: an address in the text that is not this host's own
                    var other = IpRx.Matches(all).Select(m => m.Value).FirstOrDefault(ip => !f.HostIps.Contains(ip));
                    if (other != null)
                    {
                        dstIp = other;
                        dstHost = ipOwner.TryGetValue(other, out var o) ? o : "";
                    }
                    if (dstHost.Length == 0 && UncRx.Match(all) is { Success: true } unc && !Regex.IsMatch(unc.Groups["h"].Value, $"^{Ip}$"))
                        dstHost = unc.Groups["h"].Value;
                }

                var url = UrlRx.Match(all) is { Success: true } u ? u.Value.TrimEnd('.', ',', ')', '\'') : "";
                if (dstIp.Length == 0 && url.Length > 0 && IpRx.Match(url) is { Success: true } uip) dstIp = uip.Value;

                var notes = new List<string>
                {
                    $"Severity: {f.Severity}",
                    $"Likelihood: {LikelihoodScale.Label(f.Likelihood)}" + (f.IsAnalystAssessed ? " (set by analyst)" : ""),
                    "Time UTC",
                };
                if (detail.Length > 0) notes.Add(detail);
                if (!string.IsNullOrWhiteSpace(f.Note)) notes.Add("Analyst note: " + f.Note.Trim());
                notes.Add($"Collection: {f.Collection}");

                rows.Add(new Row(f.TimeUtc, new[]
                {
                    "",                                    // date/time (written as a date cell)
                    $"{f.Kind}: {f.SourceText}",
                    f.Host,
                    hostIps,
                    title,
                    AccountOf(title + " " + detail),
                    srcHost,
                    srcIp,
                    dstHost,
                    url,
                    dstIp,
                    "",                                    // Mitre Framework: analyst
                    string.Join(" · ", notes),
                    data.Analyst,
                    "",                                    // ReportHeading: analyst
                }));
            }
            return rows;
        }

        private static List<Row> M365Rows(CaseReportData data, IEnumerable<ReportFinding> findings)
        {
            var rows = new List<Row>();
            foreach (var f in findings.OrderBy(f => f.TimeUtc ?? DateTime.MaxValue))
            {
                var (title, detail) = CaseReport.SplitTitle(f.Text);
                var all = f.Text;
                // Accounts from the finding itself, not from lists in its detail (a spray lists every account tried)
                var emails = EmailRx.Matches(title).Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                // The account the finding is about comes first in the text ("Inbox rule … for jdoe@…", "jdoe@… added to role … by admin@…")
                var account = emails.FirstOrDefault() ?? "";
                // Impossible travel and a session in two countries name the usual place first and the new one last:
                // the new one is the source worth tracking
                bool newLast = title.StartsWith("Impossible travel", StringComparison.OrdinalIgnoreCase)
                               || title.StartsWith("Session of", StringComparison.OrdinalIgnoreCase);
                var ips = IpRx.Matches(title).Select(m => m.Value).ToList();
                var sourceIp = newLast && ips.Count > 0 ? ips[^1]
                             : FromRx.Match(all) is { Success: true } from ? from.Groups["ip"].Value
                             : ips.FirstOrDefault() ?? (IpRx.Match(all) is { Success: true } ip ? ip.Value : "");
                var locations = LocationRx.Matches(title).Select(m => m.Groups["l"].Value).ToList();
                var location = locations.Count == 0 ? "" : newLast ? locations[^1] : locations[0];
                // What it acted on: a quoted name (rule, application, role), else another address (forwarding target, the account reset)
                var target = QuotedRx.Match(title) is { Success: true } q ? q.Groups["v"].Value
                           : emails.Skip(1).FirstOrDefault() ?? "";
                var source = f.SourceText.Replace("M365-", "", StringComparison.OrdinalIgnoreCase);

                var notes = new List<string>
                {
                    $"Severity: {f.Severity}",
                    $"Likelihood: {LikelihoodScale.Label(f.Likelihood)}" + (f.IsAnalystAssessed ? " (set by analyst)" : ""),
                    "Time UTC",
                };
                if (detail.Length > 0) notes.Add(detail);
                if (!string.IsNullOrWhiteSpace(f.Note)) notes.Add("Analyst note: " + f.Note.Trim());
                notes.Add($"Collection: {f.Collection}");

                rows.Add(new Row(f.TimeUtc, new[]
                {
                    "",                                    // date/time (written as a date cell)
                    $"M365: {source}",
                    f.Host,
                    account,
                    sourceIp,
                    location,
                    title,
                    target,
                    "",                                    // Mitre Framework: analyst
                    string.Join(" · ", notes),
                    data.Analyst,
                    "",                                    // ReportHeading: analyst
                }));
            }
            return rows;
        }

        internal static string AccountOf(string text)
        {
            foreach (var rx in AccountRx)
                foreach (Match m in rx.Matches(text))
                {
                    var a = m.Groups["a"].Value.Trim('.', ',', ')');
                    if (a.Length < 2 || NotAccounts.Contains(a) || a.All(char.IsDigit) || IpRx.IsMatch(a)) continue;
                    var slash = a.IndexOf('\\');
                    if (slash > 0 && NotDomains.Contains(a[..slash])) continue;   // registry / file path, not DOMAIN\user
                    return a;
                }
            return "";
        }

        // ── .xlsx ────────────────────────────────────────────────────────
        /// <summary>The workbook: the Hosts sheet always, the M365 sheet when there are M365 rows.</summary>
        public static void Write(string path, Tracker tracker)
        {
            var sheets = new List<(string Name, string[] Columns, double[] Widths, List<Row> Rows)>
                { (HostsSheet, Columns, Widths, tracker.Hosts) };
            if (tracker.M365.Count > 0) sheets.Add((M365Sheet, M365Columns, M365Widths, tracker.M365));

            using var doc = SpreadsheetDocument.Create(path, SpreadsheetDocumentType.Workbook);
            var wb = doc.AddWorkbookPart();
            wb.Workbook = new Workbook();
            var styles = wb.AddNewPart<WorkbookStylesPart>();
            styles.Stylesheet = Styles();
            styles.Stylesheet.Save();

            var sheetList = new Sheets();
            var names = new DefinedNames();
            for (int i = 0; i < sheets.Count; i++)
            {
                var (name, columns, widths, rows) = sheets[i];
                var sheetData = new SheetData();
                sheetData.Append(new DocumentFormat.OpenXml.Spreadsheet.Row(columns.Select(c => TextCell(c, 1))) { RowIndex = 1 });
                uint r = 1;
                foreach (var row in rows)
                {
                    r++;
                    var cells = new List<Cell> { row.Time.HasValue ? DateCell(row.Time.Value) : TextCell("", 0) };
                    cells.AddRange(row.Values.Skip(1).Select(v => TextCell(v, 0)));
                    sheetData.Append(new DocumentFormat.OpenXml.Spreadsheet.Row(cells) { RowIndex = r });
                }

                var cols = new DocumentFormat.OpenXml.Spreadsheet.Columns(widths.Select((w, c) =>
                    new Column { Min = (uint)(c + 1), Max = (uint)(c + 1), Width = w, CustomWidth = true }));
                var lastCol = ColumnLetter(columns.Length);
                var ws = wb.AddNewPart<WorksheetPart>();
                ws.Worksheet = new Worksheet(
                    new SheetViews(new SheetView(new Pane
                    {
                        VerticalSplit = 1, TopLeftCell = "A2", ActivePane = PaneValues.BottomLeft, State = PaneStateValues.Frozen,
                    }) { TabSelected = i == 0, WorkbookViewId = 0 }),
                    cols,
                    sheetData,
                    new AutoFilter { Reference = $"A1:{lastCol}{Math.Max(r, 1)}" });
                ws.Worksheet.Save();
                sheetList.Append(new Sheet { Id = wb.GetIdOfPart(ws), SheetId = (uint)(i + 1), Name = name });
                names.Append(new DefinedName
                {
                    Name = "_xlnm._FilterDatabase", LocalSheetId = (uint)i, Hidden = true,
                    Text = $"'{name}'!$A$1:${lastCol}${Math.Max(r, 1)}",
                });
            }
            wb.Workbook.Append(sheetList, names);
            wb.Workbook.Save();
        }

        private static string ColumnLetter(int n)
        {
            var s = "";
            for (; n > 0; n = (n - 1) / 26) s = (char)('A' + (n - 1) % 26) + s;
            return s;
        }

        private static Cell TextCell(string? value, uint style) => new()
        {
            DataType = CellValues.InlineString,
            StyleIndex = style,
            InlineString = new InlineString(new Text(Clean(value)) { Space = SpaceProcessingModeValues.Preserve }),
        };

        private static Cell DateCell(DateTime t) => new()
        {
            StyleIndex = 2,
            CellValue = new CellValue(t.ToOADate().ToString(CultureInfo.InvariantCulture)),
        };

        /// <summary>XML can't hold control characters; Excel cells hold at most 32767.</summary>
        private static string Clean(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var t = new string(s.Where(c => c == '\t' || c == '\n' || c >= ' ').ToArray());
            return t.Length > 32000 ? t[..32000] + "…" : t;
        }

        private static Stylesheet Styles() => new(
            new NumberingFormats(new NumberingFormat { NumberFormatId = 164, FormatCode = "yyyy-mm-dd hh:mm:ss" }) { Count = 1 },
            new Fonts(new Font(new FontSize { Val = 11 }, new FontName { Val = "Calibri" }),
                      new Font(new Bold(), new FontSize { Val = 11 }, new FontName { Val = "Calibri" })) { Count = 2 },
            new Fills(new Fill(new PatternFill { PatternType = PatternValues.None }),
                      new Fill(new PatternFill { PatternType = PatternValues.Gray125 })) { Count = 2 },
            new Borders(new Border()) { Count = 1 },
            new CellStyleFormats(new CellFormat()) { Count = 1 },
            new CellFormats(
                new CellFormat(),                                                   // 0 text
                new CellFormat { FontId = 1, ApplyFont = true },                    // 1 header
                new CellFormat { NumberFormatId = 164, ApplyNumberFormat = true }) // 2 date/time
            { Count = 3 });
    }
}
