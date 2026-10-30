using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Identity.Application.Abstractions.Security;

namespace Identity.Infrastructure.Security;

public sealed class SecretEncryptionOptions
{
    public const string Section = "SecretEncryption";

    /// <summary>
    /// AES-256 keys (32 random bytes, base64). The first one encrypts; all of them decrypt, so a key can be
    /// rotated by adding a new first entry and keeping the old one until every secret has been re-encrypted.
    /// </summary>
    public List<EncryptionKeyOptions> Keys { get; set; } = [];

    /// <summary>Development only: where the auto-generated key is kept (relative to the content root).</summary>
    public string DevKeyPath { get; set; } = ".keys/dev-secret-encryption.key";
}

public sealed class EncryptionKeyOptions
{
    public string KeyId { get; set; } = "";
    public string Key { get; set; } = "";
}

/// <summary>
/// AES-256-GCM: "v1.{keyId}.{base64url(nonce | tag | ciphertext)}". The associated data (e.g. the user id) is
/// authenticated but not stored, so a ciphertext copied into another user's row fails to decrypt.
/// Without configured keys: Development generates one in <see cref="SecretEncryptionOptions.DevKeyPath"/>,
/// Testing uses an in-memory key, any other environment refuses to start.
/// </summary>
public sealed class AesGcmSecretProtector : ISecretProtector
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly IReadOnlyList<(string Id, byte[] Key)> _keys;

    public AesGcmSecretProtector(IOptions<SecretEncryptionOptions> options, IHostEnvironment env)
    {
        var opt = options.Value;
        var configured = opt.Keys.Where(k => !string.IsNullOrWhiteSpace(k.Key)).ToList();
        _keys = configured.Count > 0
            ? configured.Select(k => (Id: Require(k.KeyId), Key: Decode(k.Key))).ToList()
            : [FallbackKey(opt, env)];
    }

    public string Protect(byte[] secret, string associatedData)
    {
        var (id, key) = _keys[0];
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var output = new byte[NonceSize + TagSize + secret.Length];
        nonce.CopyTo(output, 0);

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, secret, output.AsSpan(NonceSize + TagSize), output.AsSpan(NonceSize, TagSize), Encoding.UTF8.GetBytes(associatedData));
        return $"v1.{id}.{Base64UrlEncoder.Encode(output)}";
    }

    public byte[]? Unprotect(string protectedValue, string associatedData)
    {
        var parts = protectedValue.Split('.');
        if (parts is not ["v1", var id, var payload]) return null;
        var key = _keys.FirstOrDefault(k => k.Id == id).Key;
        if (key is null) return null;

        try
        {
            var data = Base64UrlEncoder.DecodeBytes(payload);
            if (data.Length < NonceSize + TagSize) return null;
            var plaintext = new byte[data.Length - NonceSize - TagSize];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(data.AsSpan(0, NonceSize), data.AsSpan(NonceSize + TagSize), data.AsSpan(NonceSize, TagSize),
                plaintext, Encoding.UTF8.GetBytes(associatedData));
            return plaintext;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return null;
        }
    }

    private static (string, byte[]) FallbackKey(SecretEncryptionOptions opt, IHostEnvironment env)
    {
        if (env.IsEnvironment("Testing")) return ("test", RandomNumberGenerator.GetBytes(32));
        if (!env.IsDevelopment())
            throw new InvalidOperationException("SecretEncryption:Keys must be configured outside Development (32 random bytes, base64).");

        var path = Path.GetFullPath(Path.Combine(env.ContentRootPath, opt.DevKeyPath));
        if (!File.Exists(path))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        }
        return ("dev", Decode(File.ReadAllText(path)));
    }

    private static byte[] Decode(string base64)
    {
        var key = Convert.FromBase64String(base64.Trim());
        if (key.Length != 32) throw new InvalidOperationException($"Secret encryption keys must be 32 bytes (got {key.Length}).");
        return key;
    }

    private static string Require(string keyId) =>
        string.IsNullOrWhiteSpace(keyId) || keyId.Contains('.')
            ? throw new InvalidOperationException("Every SecretEncryption key needs a KeyId without dots.")
            : keyId;
}
