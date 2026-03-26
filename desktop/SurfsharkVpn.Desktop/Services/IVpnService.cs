using SurfsharkVpn.Desktop.Models;

namespace SurfsharkVpn.Desktop.Services;

public interface IVpnService
{
    Task<IReadOnlyList<ServerEntry>> GetOpenVpnServersAsync(string openVpnDirectory, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ServerEntry>> GetWireGuardServersAsync(string wireGuardDirectory, CancellationToken cancellationToken = default);

    Task<(bool Ok, string Message)> ConnectOpenVpnAsync(string configFile, CancellationToken cancellationToken = default);
    Task<(bool Ok, string Message)> ConnectWireGuardAsync(string configFile, CancellationToken cancellationToken = default);
    Task<(bool Ok, string Message)> DisconnectAsync(CancellationToken cancellationToken = default);
    Task<(bool Ok, string Message)> ReconnectNowAsync(CancellationToken cancellationToken = default);

    VpnStatus GetStatus();
}
