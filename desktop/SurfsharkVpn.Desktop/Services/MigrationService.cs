using System.Text.Json;
using System.IO;

namespace SurfsharkVpn.Desktop.Services;

public sealed class MigrationService : IMigrationService
{
    private static readonly string[] KnownFiles =
    [
        "favorites.json",
        "recent.json",
        "profiles.json",
        "autostart.json",
        "settings.json",
        "last_success.json",
    ];

    private readonly IDataStore _store;

    public MigrationService(IDataStore store)
    {
        _store = store;
    }

    public MigrationResult ImportFromDirectory(string sourceDataDirectory)
    {
        var result = new MigrationResult();
        if (string.IsNullOrWhiteSpace(sourceDataDirectory) || !Directory.Exists(sourceDataDirectory))
        {
            result.Messages.Add("Source directory not found.");
            return result;
        }

        foreach (var file in KnownFiles)
        {
            var src = Path.Combine(sourceDataDirectory, file);
            if (!File.Exists(src))
            {
                continue;
            }

            try
            {
                // Validate JSON before copy to avoid importing corrupt files.
                _ = JsonDocument.Parse(File.ReadAllText(src));
                var dst = Path.Combine(_store.DataDirectory, file);
                File.Copy(src, dst, true);
                result.ImportedFiles++;
                result.Messages.Add($"Imported {file}");
            }
            catch (Exception ex)
            {
                result.Messages.Add($"Skipped {file}: {ex.Message}");
            }
        }

        if (result.ImportedFiles == 0)
        {
            result.Messages.Add("No compatible files were imported.");
        }

        return result;
    }
}
