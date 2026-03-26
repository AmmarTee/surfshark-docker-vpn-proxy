namespace SurfsharkVpn.Desktop.Models;

public sealed class ServerEntry
{
    public string File { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public string CityCode { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
}
