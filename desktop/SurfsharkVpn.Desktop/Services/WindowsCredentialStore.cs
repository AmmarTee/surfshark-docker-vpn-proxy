namespace SurfsharkVpn.Desktop.Services;

public sealed class WindowsCredentialStore : ICredentialStore
{
    public bool SaveSecret(string key, string username, string secret)
    {
        // Placeholder for Windows Credential Manager API integration.
        // Next implementation step: use CredWrite/CredRead P/Invoke wrappers.
        return false;
    }

    public (bool Found, string Username, string Secret) ReadSecret(string key)
    {
        return (false, string.Empty, string.Empty);
    }

    public bool DeleteSecret(string key)
    {
        return false;
    }
}
