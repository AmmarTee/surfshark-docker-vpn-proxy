# Windows App Implementation Notes

## Current Status

A standalone WPF desktop project scaffold now exists at:

- desktop/SurfsharkVpn.Desktop

This is intentionally independent from Docker and prepared for native engine integration.

## Implemented in This Pass

1. Project scaffold (WPF, net8.0-windows).
2. Main window shell with left navigation and primary connect/stop/reconnect actions.
3. Core architecture primitives:
   - ObservableObject
   - RelayCommand
4. Domain models for settings, autostart, profiles, recent, servers, status, and events.
5. Data store in AppData:
   - %AppData%/SurfsharkVpnDesktop/data
6. Migration service:
   - Imports favorites.json, recent.json, profiles.json, autostart.json, settings.json, last_success.json
   - Validates JSON before importing
7. Native VPN service stub:
   - Parses OpenVPN and WireGuard filename patterns
   - Provides initial status/connect/disconnect/reconnect methods for UI flow wiring
8. Startup service:
   - HKCU Run registration helper
9. Credential store interface + placeholder implementation for Windows Credential Manager

## Known Gaps (Next Implementation)

1. Wire actual process orchestration:
   - openvpn.exe start/stop/status
   - wireguard CLI start/stop/status
2. Proxy process orchestration:
   - microsocks equivalent on Windows
   - HTTP proxy process and dynamic reconfiguration
3. Credential Manager concrete implementation (CredRead/CredWrite).
4. Full page UIs:
   - server list/search/filter/favorites/recent
   - settings editor
   - profiles CRUD
   - merged logs/events with rotating file writer and live tail
5. Tray icon and quick actions.
6. Elevation boundary (request admin when privileged operations run).

## Prerequisites Required on This Machine

- Install .NET 8 SDK (required to build WPF project).
- Ensure OpenVPN and WireGuard CLIs are installed and discoverable in PATH.

## Build Commands (after installing SDK)

```powershell
cd desktop/SurfsharkVpn.Desktop
dotnet restore
dotnet build
```
