namespace SurfsharkVpn.Desktop.Models;

public sealed class ConnectionProfile
{
    public string Name { get; set; } = string.Empty;
    public string Server { get; set; } = string.Empty;
    public string VpnMode { get; set; } = "openvpn";
    public string Protocol { get; set; } = "UDP";
    public int SocksPort { get; set; } = 1080;
    public int HttpPort { get; set; } = 8888;
}
