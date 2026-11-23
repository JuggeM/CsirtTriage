using CsirtTriage.Core.Case;

namespace CsirtTriage.WPF.ViewModels;

/// <summary>One source the analyst can switch on or off (a UAC parser or a KAPE module).</summary>
public sealed class SourceToggle : ViewModelBase
{
    private readonly Func<bool> _get;
    private readonly Action<bool> _set;

    public SourceToggle(CollectionKind kind, string category, string name, string detail, string description,
                        Func<bool> get, Action<bool> set)
    {
        Kind = kind; Category = category; Name = name; Detail = detail; Description = description;
        _get = get; _set = set;
    }

    public CollectionKind Kind { get; }
    public string Category { get; }
    public string Name { get; }
    /// <summary>Files it reads, e.g. "EvtxECmd: *_EvtxECmd_Output.csv".</summary>
    public string Detail { get; }
    /// <summary>What it detects and why it matters (shown under the name).</summary>
    public string Description { get; }

    public bool IsEnabled
    {
        get => _get();
        set { if (_get() != value) { _set(value); OnPropertyChanged(); } }
    }

    public void Refresh() => OnPropertyChanged(nameof(IsEnabled));
}

/// <summary>Every UAC parser and KAPE module, grouped by category, bound to the run settings.</summary>
public static class SourceCatalog
{
    public static List<SourceToggle> Create(TriageSettings s) => new()
    {
            new(CollectionKind.Uac, "Logs", "Auth / Secure", "SSH, PAM, sudo",
                "Parses /var/log/auth.log and /var/log/secure. Detects failed and successful SSH logins, sudo usage, PAM errors, and new user creation. Runs brute-force detection across all source IPs. High forensic value usually the first place to check for initial access.",
                () => s.Uac.ParseAuth, v => s.Uac.ParseAuth = v),
            new(CollectionKind.Uac, "Persistence and system state", "Crontab scanner", "Job definitions, persistence",
                "Scans actual crontab definition files for suspicious persistent job entries: /etc/crontab, /etc/cron.d/*, /var/spool/cron/crontabs/* (Debian/Ubuntu), and /var/spool/cron/* (RHEL/CentOS). Flags reverse shells, downloaders to /tmp, base64 decoders, and other attacker-planted persistence. Complements Syslog which catches runtime cron execution. High forensic value attackers frequently use cron for persistence.",
                () => s.Uac.ParseCrontab, v => s.Uac.ParseCrontab = v),
            new(CollectionKind.Uac, "Logs", "Messages", "/var/log/messages",
                "Parses /var/log/messages. Covers general system activity, daemon starts/stops, kernel messages, and application errors. Useful for establishing a timeline around the incident. Filters known benign noise automatically.",
                () => s.Uac.ParseMessages, v => s.Uac.ParseMessages = v),
            new(CollectionKind.Uac, "Logs", "Syslog", "syslog, kern.log + cron events",
                "Parses /var/log/syslog and kern.log. Captures kernel-level events: OOM kills, kernel panics, segfaults, hardware errors, RAID degraded, and I/O errors. Also detects suspicious cron CMD executions (Debian/Ubuntu write cron logs to syslog) reverse shells, downloaders, and one-liner executions planted in cron jobs. Essential on Debian/Ubuntu where cron does not have a separate log file.",
                () => s.Uac.ParseSyslog, v => s.Uac.ParseSyslog = v),
            new(CollectionKind.Uac, "Logs", "Web logs", "Apache, Nginx access",
                "Parses Apache and Nginx access logs. Detects web brute-force attacks, directory traversal, command injection, and suspicious user agents. Flags high request rates per IP. Useful for identifying web application exploitation and C2 over HTTP.",
                () => s.Uac.ParseWebLogs, v => s.Uac.ParseWebLogs = v),
            new(CollectionKind.Uac, "Logs", "Docker", "Containers & events",
                "Parses Docker daemon logs, container events, and image metadata. Detects privileged container launches, unusual image pulls, and container escapes. Attackers may abuse Docker to gain host root access or run cryptominers in isolated containers.",
                () => s.Uac.ParseDocker, v => s.Uac.ParseDocker = v),
            new(CollectionKind.Uac, "Logs", "Audit log", "auditd records",
                "Parses /var/log/audit/audit.log (auditd). Provides syscall-level visibility: file access, process execution (execve), privilege changes, and network connections. Extremely high forensic value when auditd rules are in place. Can reveal attacker tools, lateral movement, and data staging.",
                () => s.Uac.ParseAudit, v => s.Uac.ParseAudit = v),
            new(CollectionKind.Uac, "Persistence and system state", "Live response", "UAC live data",
                "Parses UAC live response artefacts: user accounts, sudoers, loaded kernel modules, ARP cache, and routing tables. Provides a system state snapshot at collection time. Useful for identifying privilege escalation paths, network pivoting, and unauthorised accounts.",
                () => s.Uac.ParseLiveResponse, v => s.Uac.ParseLiveResponse = v),
            new(CollectionKind.Uac, "Persistence and system state", "Body file", "File timeline scoring",
                "Parses the UAC bodyfile.txt (mactime/TSK format). Scores every file entry based on path, suspicious keywords, executable extensions, recency, and size. Only entries above the minimum score threshold appear in QuickWins. High value for finding dropped tools, webshells, and attacker staging areas. Can be slow on large collections disable if not needed.",
                () => s.Uac.ParseBodyFile, v => s.Uac.ParseBodyFile = v),
            new(CollectionKind.Uac, "Logs", "systemd Journal", "user-*.journal binary logs",
                "Parses binary systemd user journal files (user-1000.journal etc.). Extracts sudo commands, SSH events, shell executions, and suspicious process launches for UID 1000 and above. Forensically valuable because it captures user activity independently of bash history and is difficult to forge. Requires K4os.Compression.LZ4 NuGet package for LZ4-compressed entries.",
                () => s.Uac.ParseJournal, v => s.Uac.ParseJournal = v),
            new(CollectionKind.Uac, "User activity", "Bash history", ".bash_history, all users",
                "Parses .bash_history files from root and all user home directories. Detects reverse shells, credential access (/etc/shadow, hashcat, john), droppers (wget/curl to /tmp), SUID manipulation, lateral movement via SSH, and anti-forensics (history -c, HISTFILE=/dev/null, shred). When HISTTIMEFORMAT is set, timestamps are parsed and large time gaps between commands are flagged.",
                () => s.Uac.ParseBashHistory, v => s.Uac.ParseBashHistory = v),
            new(CollectionKind.Uac, "User activity", "Zsh history", ".zsh_history, all users",
                "Parses .zsh_history files from root and all user home directories. Supports Zsh extended history format with built-in timestamps and multi-line command continuation. Uses the same suspicious keyword detection as bash history. Increasingly common on modern Linux and macOS systems.",
                () => s.Uac.ParseZsh, v => s.Uac.ParseZsh = v),
            new(CollectionKind.Uac, "User activity", "Vim info", ".viminfo, shell escapes, file access",
                "Parses .viminfo files. Detects shell escapes (:!cmd) which execute arbitrary commands from inside Vim and bypass bash_history entirely. Also surfaces sensitive files opened in Vim (/etc/shadow, id_rsa, authorized_keys) and suspicious search terms typed inside the editor. High value attackers frequently use Vim's shell escape to avoid history logging.",
                () => s.Uac.ParseVimInfo, v => s.Uac.ParseVimInfo = v),
            new(CollectionKind.Uac, "User activity", "Database history", "MySQL, PostgreSQL, SQLite, Redis",
                "Parses .mysql_history, .psql_history, .sqlite_history, and .rediscli_history. Detects credential manipulation (ALTER USER, CREATE USER with passwords), data exfiltration (SELECT INTO OUTFILE, COPY TO), privilege escalation (GRANT ALL), UDF shell execution, and MySQL shell escapes (\\! cmd). High value on database servers.",
                () => s.Uac.ParseDbHistory, v => s.Uac.ParseDbHistory = v),
            new(CollectionKind.Uac, "User activity", "Python history", ".python_history, REPL commands",
                "Parses .python_history from the Python interactive REPL. Detects live exploit development: os.system/subprocess calls, socket-based reverse shells, offensive imports (impacket, scapy, pwntools), exec/eval abuse, and credential file access. Commands run in the Python REPL never appear in bash_history making this a blind spot often missed in investigations.",
                () => s.Uac.ParsePythonHistory, v => s.Uac.ParsePythonHistory = v),
            new(CollectionKind.Uac, "User activity", "Wget HSTS", ".wget-hsts, download history",
                "Parses .wget-hsts which records every HTTPS host wget connected to with timestamps. Persists even after downloaded files are deleted making it a reliable C2 and dropper download record. Flags raw IPs, throwaway TLDs (.xyz, .tk, .top), Tor (.onion), and reverse tunnel services (ngrok, DDNS). Trusted CDN and package manager domains are suppressed.",
                () => s.Uac.ParseWgetHsts, v => s.Uac.ParseWgetHsts = v),
            new(CollectionKind.Uac, "User activity", "Less history", ".lesshst, search + shell escapes",
                "Parses .lesshst from the less pager. Captures search terms typed inside less (reveals what the attacker was looking for in files they read) and shell escapes run via ! (commands that bypass bash_history entirely). Attackers who clear bash_history almost never clear .lesshst making it a reliable anti-forensics gap.",
                () => s.Uac.ParseLessHst, v => s.Uac.ParseLessHst = v),
            new(CollectionKind.Uac, "User activity", "AI coding agents", "Claude Code, Codex, Gemini, Copilot…",
                "Reads the AI agent artifacts UAC 3.4.0+ collects (Claude Code, Codex, Gemini CLI, Copilot, Cursor, Goose, OpenCode, Qwen, Kiro and others). Transcripts give every shell command the agent ran, files it wrote, URLs it fetched and the prompt behind them, with UTC timestamps. Flags reverse shells, secrets hunting (wallets, SSH keys, cloud credentials), pipe-to-shell, writes to persistence files, hooks and MCP servers that run commands, approval bypass (bypassPermissions, yolo, approval_policy=never), prompt-injection phrases in instruction files, and credential files left on disk (reported, never read).",
                () => s.Uac.ParseAiAgents, v => s.Uac.ParseAiAgents = v),
            new(CollectionKind.Uac, "Persistence and system state", "SHA1 hashes", "hash_executables.sha1",
                "Executables outside system folders worth a hash lookup, scored by path (temp, home, /dev/shm), hidden names, suspicious names and extensions. Every candidate goes to Sha1Candidates.csv for a threat-intel lookup; the top 100 are findings. A SHA1 in the case IOC list is matched here too.",
                () => s.Uac.ParseHashes, v => s.Uac.ParseHashes = v),
            new(CollectionKind.Kape, "Event logs", "Event logs", "EvtxECmd: *_EvtxECmd_Output.csv",
                "Logons and brute force (4624/4625/4771/4776), RDP (4624 type 10, 1149, 21/25), accounts and privileged groups, services (7045/4697), scheduled tasks (4698), process command lines (4688, Sysmon 1), PowerShell script blocks (4104), Defender detections and tampering, log clearing (1102/104), Kerberoasting, admin shares, WMI subscriptions, BITS.",
                () => s.Kape.AnalyseEventLogs, v => s.Kape.AnalyseEventLogs = v),
            new(CollectionKind.Kape, "Execution", "Prefetch", "PECmd: *_PECmd_Output.csv",
                "Programs that ran: known attacker and dual-use tools, executables run from staging folders (Temp, Public, PerfLogs, ProgramData, drive root). Uses all eight run times.",
                () => s.Kape.AnalysePrefetch, v => s.Kape.AnalysePrefetch = v),
            new(CollectionKind.Kape, "Execution", "Amcache", "AmcacheParser: *_Amcache_*FileEntries.csv",
                "Binaries present or run, with SHA1 for IOC matching and threat-intel lookups.",
                () => s.Kape.AnalyseAmcache, v => s.Kape.AnalyseAmcache = v),
            new(CollectionKind.Kape, "Execution", "ShimCache", "AppCompatCacheParser: *AppCompatCache*.csv",
                "Binaries the system saw. Times are file modification times, not run times.",
                () => s.Kape.AnalyseShimcache, v => s.Kape.AnalyseShimcache = v),
            new(CollectionKind.Kape, "Execution", "Registry", "RECmd batch: *_RECmd_Batch_*_Output.csv",
                "Autoruns, services, UserAssist, BAM, RunMRU and every other batch value checked for tools, staging paths and attack command lines; Defender exclusions; host name and IP addresses.",
                () => s.Kape.AnalyseRegistry, v => s.Kape.AnalyseRegistry = v),
            new(CollectionKind.Kape, "User activity", "LNK files", "LECmd: *_LECmd_Output.csv",
                "Files users opened: tools, staging folders, malicious shortcut arguments, admin shares, removable media.",
                () => s.Kape.AnalyseLnk, v => s.Kape.AnalyseLnk = v),
            new(CollectionKind.Kape, "User activity", "Jump lists", "JLECmd: *_AutomaticDestinations.csv",
                "Same checks as LNK files, per application jump list.",
                () => s.Kape.AnalyseJumpLists, v => s.Kape.AnalyseJumpLists = v),
            new(CollectionKind.Kape, "File system", "$MFT", "MFTECmd: *_MFTECmd_$MFT_Output.csv",
                "Files on disk (and deleted MFT entries): tools, executables in staging folders, internet downloads (Zone.Identifier), timestomping, large archives, mass ransom notes.",
                () => s.Kape.AnalyseMft, v => s.Kape.AnalyseMft = v),
            new(CollectionKind.Kape, "File system", "USN journal", "MFTECmd: *_MFTECmd_$J_Output.csv",
                "Tools created, renamed or deleted; prefetch files created for tools (execution evidence even after the .pf is gone); mass ransom notes.",
                () => s.Kape.AnalyseUsnJournal, v => s.Kape.AnalyseUsnJournal = v),
            new(CollectionKind.Kape, "File system", "Recycle Bin", "RBCmd: *_RBCmd_Output.csv",
                "Tools and large archives the user deleted.",
                () => s.Kape.AnalyseRecycleBin, v => s.Kape.AnalyseRecycleBin = v),
            new(CollectionKind.Kape, "User activity", "Shellbags", "SBECmd output",
                "Folders users browsed (also deleted ones): tool and loot folder names, admin shares.",
                () => s.Kape.AnalyseShellbags, v => s.Kape.AnalyseShellbags = v),
            new(CollectionKind.Kape, "Network and web", "SRUM (network and app usage)", "SrumECmd: *_NetworkUsages_ / *_AppResourceUseInfo_Output.csv",
                "Bytes sent and received per app per hour: tools or staged binaries that uploaded data (exfiltration), large uploads, tools that ran.",
                () => s.Kape.AnalyseSrum, v => s.Kape.AnalyseSrum = v),
            new(CollectionKind.Kape, "Event logs", "Sigma (Hayabusa / Chainsaw)", "CSV with 'hayabusa' or 'chainsaw' in the name, or sigma.csv",
                "Sigma hits from Hayabusa (dfir-timeline CSV) or Chainsaw (hunt --csv): one finding per rule, critical/high/medium/low by the rule level; informational hits are skipped.",
                () => s.Kape.AnalyseSigma, v => s.Kape.AnalyseSigma = v),
            new(CollectionKind.Kape, "User activity", "Browser history and downloads", "SQLECmd: *_ChromiumBrowser_* / *_Firefox_* CSV",
                "Visits to file sharing, paste, tunnel and remote-access sites and to raw IP addresses; downloads of known tools, into staging folders, or of executables from those sites (suspiciousDomains in rules.json).",
                () => s.Kape.AnalyseBrowser, v => s.Kape.AnalyseBrowser = v),
            new(CollectionKind.Kape, "Execution", "PowerShell history", "Raw: PSReadLine\\ConsoleHost_history.txt",
                "Commands typed in PowerShell (PSReadLine), per user: command-line rules, known tools and staging folders. Raw file from the KAPE output or the extracted collection in Decompressed; no timestamps.",
                () => s.Kape.AnalysePowerShellHistory, v => s.Kape.AnalysePowerShellHistory = v),
            new(CollectionKind.Kape, "Network and web", "Web server logs (IIS / Tomcat)", "Raw: u_ex*.log, localhost_access_log*.txt",
                "IIS (W3C) and Tomcat access logs: webshells, scripts uploaded with PUT, Tomcat manager deploys, injection attempts, scanners and web login brute force (web* patterns in rules.json). Raw files from the KAPE output or Decompressed.",
                () => s.Kape.AnalyseWebLogs, v => s.Kape.AnalyseWebLogs = v),
            new(CollectionKind.M365, "Unified audit log", "Sign-ins", "UserLoggedIn / UserLoginFailed",
                "Entra ID sign-ins: brute force and brute force that succeeded, password spray (many accounts from one IP), legacy authentication (BAV2ROPC) and scripted clients (python, Go, curl, AADInternals…), one account from many IPs in a day. Successful sign-ins go to Logons.csv, so an attacker IP seen on case hosts too is linked.",
                () => s.M365.AnalyseSignIns, v => s.M365.AnalyseSignIns = v),
            new(CollectionKind.M365, "Unified audit log", "Mailbox", "Exchange admin and mailbox operations",
                "Inbox rules that forward, delete or hide mail (RSS Feeds, Archive…) with BEC keywords (invoice, payment…), mailbox forwarding to external domains, FullAccess and SendAs permissions, transport rules, audit logging switched off, IMAP/POP enabled, eDiscovery searches and exports.",
                () => s.M365.AnalyseMailbox, v => s.M365.AnalyseMailbox = v),
            new(CollectionKind.M365, "Unified audit log", "Directory", "Entra ID directory operations",
                "Admin role assignments (Global Administrator and other privileged roles are critical), MFA methods added, removed or disabled, password resets, accounts created or deleted, consent to applications, credentials added to apps, domain federation changes, conditional access changes.",
                () => s.M365.AnalyseDirectory, v => s.M365.AnalyseDirectory = v),
            new(CollectionKind.M365, "Unified audit log", "SharePoint / OneDrive", "FileDownloaded, AnonymousLinkCreated",
                "Mass downloads (many files by one account within an hour) and 'Anyone' sharing links.",
                () => s.M365.AnalyseFiles, v => s.M365.AnalyseFiles = v),
            new(CollectionKind.M365, "Unified audit log", "Mail access", "MailItemsAccessed",
                "Bursts of mail items accessed in one mailbox within an hour (mailbox read through a stolen session or app), with the client IPs.",
                () => s.M365.AnalyseMailAccess, v => s.M365.AnalyseMailAccess = v),
    };
}
