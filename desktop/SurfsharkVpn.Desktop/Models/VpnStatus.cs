namespace SurfsharkVpn.Desktop.Models;

public sealed class VpnStatus
{
    public bool Connected { get; set; }
    public string VpnMode { get; set; } = "openvpn";
    public string? CurrentServer { get; set; }
    public string? VpnIp { get; set; }
    public bool Reconnecting { get; set; }
    public int ReconnectAttempts { get; set; }
    public string? LastReconnectReason { get; set; }
    public string? LastReconnectError { get; set; }
    public string LastAction { get; set; } = "idle";
    public double? ConnectedSince { get; set; }
}
