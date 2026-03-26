using Microsoft.Win32;

namespace SurfsharkVpn.Desktop.Services;

public sealed class StartupService : IStartupService
{
    private const string RunKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private const string AppName = "SurfsharkVpnDesktop";

    public bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: false);
        return key?.GetValue(AppName) is string value && !string.IsNullOrWhiteSpace(value);
    }

    public void Enable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true)
            ?? Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
        var exe = Environment.ProcessPath ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(exe))
        {
            key.SetValue(AppName, $"\"{exe}\" --minimized", RegistryValueKind.String);
        }
    }

    public void Disable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
        key?.DeleteValue(AppName, throwOnMissingValue: false);
    }
}
