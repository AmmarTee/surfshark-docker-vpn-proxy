using SurfsharkVpn.Desktop.Models;

namespace SurfsharkVpn.Desktop.Services;

public interface IDataStore
{
    string DataDirectory { get; }

    AppSettings LoadSettings();
    void SaveSettings(AppSettings settings);

    AutostartConfig LoadAutostart();
    void SaveAutostart(AutostartConfig config);

    List<string> LoadFavorites();
    void SaveFavorites(List<string> favorites);

    List<RecentConnection> LoadRecent();
    void SaveRecent(List<RecentConnection> recent);

    List<ConnectionProfile> LoadProfiles();
    void SaveProfiles(List<ConnectionProfile> profiles);
}
