using System.Text.RegularExpressions;
using System.IO;
using SurfsharkVpn.Desktop.Models;

namespace SurfsharkVpn.Desktop.Services;

public sealed class NativeVpnService : IVpnService
{
    private static readonly Regex OpenVpnPattern = new("^([a-z]{2})-([a-z]{3})\\.prod\\.surfshark\\.com_(tcp|udp)\\.ovpn$", RegexOptions.Compiled);
    private static readonly Regex WireGuardPattern = new("^([a-z]{2})-([a-z]{3})\\.conf$", RegexOptions.Compiled);

    private VpnStatus _status = new();

    public Task<IReadOnlyList<ServerEntry>> GetOpenVpnServersAsync(string openVpnDirectory, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<IReadOnlyList<ServerEntry>>(ReadServers(openVpnDirectory, isWireGuard: false));
    }

    public Task<IReadOnlyList<ServerEntry>> GetWireGuardServersAsync(string wireGuardDirectory, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<IReadOnlyList<ServerEntry>>(ReadServers(wireGuardDirectory, isWireGuard: true));
    }

    public Task<(bool Ok, string Message)> ConnectOpenVpnAsync(string configFile, CancellationToken cancellationToken = default)
    {
        _status.Connected = true;
        _status.VpnMode = "openvpn";
        _status.CurrentServer = configFile;
        _status.LastAction = "connected";
        _status.ConnectedSince = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return Task.FromResult((true, "OpenVPN connect stub: native process wiring is next step."));
    }

    public Task<(bool Ok, string Message)> ConnectWireGuardAsync(string configFile, CancellationToken cancellationToken = default)
    {
        _status.Connected = true;
        _status.VpnMode = "wireguard";
        _status.CurrentServer = configFile;
        _status.LastAction = "connected";
        _status.ConnectedSince = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return Task.FromResult((true, "WireGuard connect stub: native process wiring is next step."));
    }

    public Task<(bool Ok, string Message)> DisconnectAsync(CancellationToken cancellationToken = default)
    {
        _status.Connected = false;
        _status.LastAction = "disconnected";
        _status.ConnectedSince = null;
        return Task.FromResult((true, "Disconnected."));
    }

    public Task<(bool Ok, string Message)> ReconnectNowAsync(CancellationToken cancellationToken = default)
    {
        if (!_status.Connected)
        {
            return Task.FromResult((false, "No active connection to reconnect."));
        }

        _status.Reconnecting = true;
        _status.ReconnectAttempts = 1;
        _status.LastReconnectReason = "manual";
        _status.LastAction = "reconnected";
        _status.Reconnecting = false;
        _status.ReconnectAttempts = 0;
        return Task.FromResult((true, "Reconnect requested."));
    }

    public VpnStatus GetStatus() => _status;

    private static List<ServerEntry> ReadServers(string directory, bool isWireGuard)
    {
        var output = new List<ServerEntry>();
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return output;
        }

        var extension = isWireGuard ? "*.conf" : "*.ovpn";
        foreach (var path in Directory.EnumerateFiles(directory, extension))
        {
            var file = Path.GetFileName(path);
            if (isWireGuard)
            {
                var match = WireGuardPattern.Match(file);
                if (!match.Success)
                {
                    continue;
                }

                output.Add(new ServerEntry
                {
                    File = file,
                    CountryCode = match.Groups[1].Value.ToUpperInvariant(),
                    CityCode = match.Groups[2].Value,
                    Country = match.Groups[1].Value.ToUpperInvariant(),
                    City = match.Groups[2].Value.ToUpperInvariant(),
                    Protocol = "WG",
                });
            }
            else
            {
                var match = OpenVpnPattern.Match(file);
                if (!match.Success)
                {
                    continue;
                }

                output.Add(new ServerEntry
                {
                    File = file,
                    CountryCode = match.Groups[1].Value.ToUpperInvariant(),
                    CityCode = match.Groups[2].Value,
                    Country = match.Groups[1].Value.ToUpperInvariant(),
                    City = match.Groups[2].Value.ToUpperInvariant(),
                    Protocol = match.Groups[3].Value.ToUpperInvariant(),
                });
            }
        }

        return output.OrderBy(x => x.File, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
