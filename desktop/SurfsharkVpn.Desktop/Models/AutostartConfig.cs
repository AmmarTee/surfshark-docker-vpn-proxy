namespace SurfsharkVpn.Desktop.Models;

public sealed class AutostartConfig
{
    public bool Enabled { get; set; }
    public string? PreferredServer { get; set; }
    public string? PreferredMode { get; set; }
    public int RetryCount { get; set; } = 3;
    public int RetryDelaySec { get; set; } = 5;
    public string FailoverScope { get; set; } = "global";
}
