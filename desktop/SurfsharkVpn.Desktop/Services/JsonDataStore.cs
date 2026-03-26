using System.Text.Json;
using System.IO;
using SurfsharkVpn.Desktop.Models;

namespace SurfsharkVpn.Desktop.Services;

public sealed class JsonDataStore : IDataStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
    };

    public string DataDirectory { get; }

    public JsonDataStore()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        DataDirectory = Path.Combine(root, "SurfsharkVpnDesktop", "data");
        Directory.CreateDirectory(DataDirectory);
    }

    public AppSettings LoadSettings() => LoadOrDefault("settings.json", new AppSettings());

    public void SaveSettings(AppSettings settings) => Save("settings.json", settings);

    public AutostartConfig LoadAutostart() => LoadOrDefault("autostart.json", new AutostartConfig());

    public void SaveAutostart(AutostartConfig config) => Save("autostart.json", config);

    public List<string> LoadFavorites() => LoadOrDefault("favorites.json", new List<string>());

    public void SaveFavorites(List<string> favorites) => Save("favorites.json", favorites);

    public List<RecentConnection> LoadRecent() => LoadOrDefault("recent.json", new List<RecentConnection>());

    public void SaveRecent(List<RecentConnection> recent) => Save("recent.json", recent);

    public List<ConnectionProfile> LoadProfiles() => LoadOrDefault("profiles.json", new List<ConnectionProfile>());

    public void SaveProfiles(List<ConnectionProfile> profiles) => Save("profiles.json", profiles);

    private T LoadOrDefault<T>(string name, T defaultValue)
    {
        var path = Path.Combine(DataDirectory, name);
        if (!File.Exists(path))
        {
            return defaultValue;
        }

        try
        {
            var json = File.ReadAllText(path);
            var value = JsonSerializer.Deserialize<T>(json, JsonOptions);
            return value ?? defaultValue;
        }
        catch
        {
            return defaultValue;
        }
    }

    private void Save<T>(string name, T value)
    {
        var path = Path.Combine(DataDirectory, name);
        var json = JsonSerializer.Serialize(value, JsonOptions);
        File.WriteAllText(path, json);
    }
}
