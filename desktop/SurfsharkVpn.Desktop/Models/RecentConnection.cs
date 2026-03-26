namespace SurfsharkVpn.Desktop.Models;

public sealed class RecentConnection
{
    public string File { get; set; } = string.Empty;
    public string VpnMode { get; set; } = "openvpn";
    public string? VpnIp { get; set; }
    public double Timestamp { get; set; }
}
