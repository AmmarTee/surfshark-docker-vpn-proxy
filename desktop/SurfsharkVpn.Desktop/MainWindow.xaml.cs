using System.Windows;
using SurfsharkVpn.Desktop.Services;
using SurfsharkVpn.Desktop.ViewModels;

namespace SurfsharkVpn.Desktop;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        var store = new JsonDataStore();
        var migration = new MigrationService(store);
        var vpnService = new NativeVpnService();

        DataContext = new MainViewModel(store, migration, vpnService);
    }
}
