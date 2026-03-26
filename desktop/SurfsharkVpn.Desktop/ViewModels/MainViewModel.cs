using System.Windows;
using System.Windows.Controls;
using System.IO;
using SurfsharkVpn.Desktop.Infrastructure;
using SurfsharkVpn.Desktop.Services;

namespace SurfsharkVpn.Desktop.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly IDataStore _store;
    private readonly IMigrationService _migration;
    private readonly IVpnService _vpn;

    private string _activePageTitle = "Servers";
    private object _activePageContent = new TextBlock { Text = "Loading...", Foreground = System.Windows.Media.Brushes.White };
    private string _connectionSummary = "Disconnected";

    public MainViewModel(IDataStore store, IMigrationService migration, IVpnService vpn)
    {
        _store = store;
        _migration = migration;
        _vpn = vpn;

        ShowServersCommand = new RelayCommand(ShowServers);
        ShowSettingsCommand = new RelayCommand(ShowSettings);
        ShowProfilesCommand = new RelayCommand(ShowProfiles);
        ShowLogsCommand = new RelayCommand(ShowLogs);
        ConnectCommand = new RelayCommand(ConnectStub);
        DisconnectCommand = new RelayCommand(DisconnectStub);
        ReconnectNowCommand = new RelayCommand(ReconnectNowStub);

        ShowServers();
        RefreshStatus();
        TryMigrateFromRepoData();
    }

    public RelayCommand ShowServersCommand { get; }
    public RelayCommand ShowSettingsCommand { get; }
    public RelayCommand ShowProfilesCommand { get; }
    public RelayCommand ShowLogsCommand { get; }
    public RelayCommand ConnectCommand { get; }
    public RelayCommand DisconnectCommand { get; }
    public RelayCommand ReconnectNowCommand { get; }

    public string ActivePageTitle
    {
        get => _activePageTitle;
        private set => SetProperty(ref _activePageTitle, value);
    }

    public object ActivePageContent
    {
        get => _activePageContent;
        private set => SetProperty(ref _activePageContent, value);
    }

    public string ConnectionSummary
    {
        get => _connectionSummary;
        private set => SetProperty(ref _connectionSummary, value);
    }

    private void ShowServers()
    {
        ActivePageTitle = "Servers";
        ActivePageContent = new TextBlock
        {
            Text = "Servers page scaffolded. Next: full list/search/filter/favorites and native connect wiring.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.White,
            FontSize = 16,
        };
    }

    private void ShowSettings()
    {
        var settings = _store.LoadSettings();
        var autostart = _store.LoadAutostart();

        ActivePageTitle = "Settings";
        ActivePageContent = new TextBlock
        {
            Text = $"Settings loaded from local store.\nSOCKS: {settings.SocksBind}:{settings.SocksPort}\nHTTP: {(settings.HttpProxyEnabled ? "on" : "off")} {settings.HttpProxyBind}:{settings.HttpProxyPort}\nAutoReconnect: {settings.AutoReconnect}\nAutoStart: {autostart.Enabled} ({autostart.FailoverScope})",
            TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.White,
            FontSize = 16,
        };
    }

    private void ShowProfiles()
    {
        var profiles = _store.LoadProfiles();
        ActivePageTitle = "Profiles";
        ActivePageContent = new TextBlock
        {
            Text = $"Profiles scaffolded. Loaded profiles: {profiles.Count}",
            TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.White,
            FontSize = 16,
        };
    }

    private void ShowLogs()
    {
        ActivePageTitle = "Logs";
        ActivePageContent = new TextBlock
        {
            Text = "Merged VPN + events log panel scaffolded. Next: rotating file log + live tail binding.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = System.Windows.Media.Brushes.White,
            FontSize = 16,
        };
    }

    private async void ConnectStub()
    {
        var result = await _vpn.ConnectOpenVpnAsync("stub.ovpn");
        MessageBox.Show(result.Message, "Connect", MessageBoxButton.OK, result.Ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        RefreshStatus();
    }

    private async void DisconnectStub()
    {
        var result = await _vpn.DisconnectAsync();
        MessageBox.Show(result.Message, "Stop", MessageBoxButton.OK, result.Ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        RefreshStatus();
    }

    private async void ReconnectNowStub()
    {
        var result = await _vpn.ReconnectNowAsync();
        MessageBox.Show(result.Message, "Reconnect", MessageBoxButton.OK, result.Ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        RefreshStatus();
    }

    private void RefreshStatus()
    {
        var status = _vpn.GetStatus();
        if (!status.Connected)
        {
            ConnectionSummary = "Disconnected";
            return;
        }

        ConnectionSummary = $"Connected via {status.VpnMode} ({status.CurrentServer})";
    }

    private void TryMigrateFromRepoData()
    {
        var candidate = Path.Combine(Environment.CurrentDirectory, "data");
        if (!Directory.Exists(candidate))
        {
            return;
        }

        var result = _migration.ImportFromDirectory(candidate);
        if (result.ImportedFiles > 0)
        {
            ActivePageContent = new TextBlock
            {
                Text = "Initial migration completed:\n" + string.Join("\n", result.Messages),
                TextWrapping = TextWrapping.Wrap,
                Foreground = System.Windows.Media.Brushes.White,
                FontSize = 14,
            };
        }
    }
}
