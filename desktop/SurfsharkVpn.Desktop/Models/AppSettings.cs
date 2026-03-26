namespace SurfsharkVpn.Desktop.Models;

public sealed class AppSettings
{
    public int SocksPort { get; set; } = 1080;
    public string SocksBind { get; set; } = "0.0.0.0";
    public bool HttpProxyEnabled { get; set; } = true;
    public int HttpProxyPort { get; set; } = 8888;
    public string HttpProxyBind { get; set; } = "0.0.0.0";
    public bool AutoReconnect { get; set; } = true;
}
