namespace SurfsharkVpn.Desktop.Models;

public sealed class AppEvent
{
    public string Ts { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}
