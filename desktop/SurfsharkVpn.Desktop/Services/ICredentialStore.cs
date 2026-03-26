namespace SurfsharkVpn.Desktop.Services;

public interface ICredentialStore
{
    bool SaveSecret(string key, string username, string secret);
    (bool Found, string Username, string Secret) ReadSecret(string key);
    bool DeleteSecret(string key);
}
