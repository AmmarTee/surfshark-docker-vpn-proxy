namespace SurfsharkVpn.Desktop.Services;

public interface IMigrationService
{
    MigrationResult ImportFromDirectory(string sourceDataDirectory);
}

public sealed class MigrationResult
{
    public int ImportedFiles { get; set; }
    public List<string> Messages { get; } = new();
}
