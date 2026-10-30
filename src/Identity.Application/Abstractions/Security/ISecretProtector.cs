namespace Identity.Application.Abstractions.Security;

/// <summary>
/// Authenticated encryption for secrets that must be read back (the TOTP key). The associated data binds a
/// ciphertext to its owner, so a value copied to another user's row does not decrypt.
/// </summary>
public interface ISecretProtector
{
    string Protect(byte[] secret, string associatedData);

    /// <returns>Null when the value is tampered with, bound to another owner or encrypted with an unknown key.</returns>
    byte[]? Unprotect(string protectedValue, string associatedData);
}
