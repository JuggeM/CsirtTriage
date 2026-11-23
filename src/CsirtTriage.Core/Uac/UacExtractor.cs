using System.Formats.Tar;
using System.IO.Compression;

namespace CsirtTriage.Core.Uac;

/// <summary>
/// Extracts one UAC archive (uac*.tar.gz, .tgz, .tar) into Decompressed\&lt;name&gt;.
/// Moved from CsirtParser's MainViewModel so it runs without a UI and per
/// collection (several archives can be extracted in parallel).
/// </summary>
public static class UacExtractor
{
    public static readonly string[] ArchivePatterns = { "uac*.tar.gz", "uac*.tgz", "uac*.tar" };

    /// <summary>Collection name for an archive: the file name without .tar.gz / .tgz / .tar.</summary>
    public static string CollectionName(string archivePath)
    {
        var name = Path.GetFileName(archivePath);
        if (name.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)) name = name[..^7];
        else if (name.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        if (name.EndsWith(".tar", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        return name;
    }

    /// <summary>
    /// A collection counts as extracted only if its final folder exists and
    /// has content. Extraction writes into a temporary sibling folder that is
    /// renamed to the final name only on success, so an interrupted or failed
    /// extraction never leaves a folder that looks finished.
    /// </summary>
    public static bool IsExtracted(string decompressDir, string collectionName)
    {
        var path = Path.Combine(decompressDir, collectionName);
        return Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any();
    }

    /// <summary>Extracts <paramref name="archivePath"/> to Decompressed\&lt;name&gt; and returns that folder.</summary>
    /// <param name="progress">Called with the number of files written so far (every 100 files).</param>
    public static string Extract(string archivePath, string decompressDir, CancellationToken ct = default,
                                 Action<long>? progress = null)
    {
        var name = CollectionName(archivePath);
        var finalPath = Path.Combine(decompressDir, name);
        // "_" prefix keeps the temp folder out of collection discovery
        var partialPath = Path.Combine(decompressDir, "_partial_" + name);

        try
        {
            // Leftovers from an earlier failed or interrupted run
            if (Directory.Exists(partialPath)) Directory.Delete(partialPath, recursive: true);
            if (Directory.Exists(finalPath) && !Directory.EnumerateFileSystemEntries(finalPath).Any())
                Directory.Delete(finalPath);
            Directory.CreateDirectory(partialPath);
            var partialPrefix = Path.GetFullPath(partialPath) + Path.DirectorySeparatorChar;

            using (var fs = File.OpenRead(archivePath))
            {
                bool plainTar = archivePath.EndsWith(".tar", StringComparison.OrdinalIgnoreCase);
                using Stream tarStream = plainTar ? fs : new GZipStream(fs, CompressionMode.Decompress);
                using var reader = new TarReader(tarStream, leaveOpen: true);

                long fileCount = 0;
                TarEntry? entry;
                while ((entry = reader.GetNextEntry(copyData: false)) != null)
                {
                    ct.ThrowIfCancellationRequested();
                    if (entry.EntryType is TarEntryType.Directory or TarEntryType.SymbolicLink or TarEntryType.HardLink)
                        continue;
                    try
                    {
                        var relPath = entry.Name.TrimStart('/', '\\');
                        var destPath = Path.GetFullPath(Path.Combine(partialPath, relPath));
                        // Path traversal guard: never write outside the collection folder
                        if (!destPath.StartsWith(partialPrefix, StringComparison.OrdinalIgnoreCase))
                            continue;
                        Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                        if (entry.DataStream != null)
                        {
                            using var outFs = File.Create(destPath);
                            entry.DataStream.CopyTo(outFs);
                        }
                        fileCount++;
                        if (fileCount % 100 == 0) progress?.Invoke(fileCount);
                    }
                    catch (IOException) { /* skip unwritable entries (names Windows cannot hold, locked files) */ }
                    catch (UnauthorizedAccessException) { }
                }
            }

            if (!Directory.EnumerateFileSystemEntries(partialPath).Any())
                throw new InvalidDataException("archive produced no files");

            // Commit: only a fully extracted collection gets its final name
            Directory.Move(partialPath, finalPath);
            return finalPath;
        }
        catch
        {
            try { if (Directory.Exists(partialPath)) Directory.Delete(partialPath, recursive: true); }
            catch { /* best effort */ }
            throw;
        }
    }
}
