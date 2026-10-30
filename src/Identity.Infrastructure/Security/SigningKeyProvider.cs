using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Infrastructure.Security;

/// <summary>
/// Loads the RSA signing keys once. Other services only ever see the public halves, through the JWKS endpoint,
/// so they can validate tokens but never mint them.
/// Without configured keys: Development generates one and keeps it in <see cref="JwtOptions.DevKeyPath"/>
/// (so restarts do not invalidate tokens), Testing uses an in-memory key, and any other environment refuses to start.
/// </summary>
public sealed class SigningKeyProvider
{
    private const int MinKeySizeBits = 2048;

    public SigningKeyProvider(IOptions<JwtOptions> options, IHostEnvironment env)
    {
        var opt = options.Value;
        var configured = opt.SigningKeys.Where(k => !string.IsNullOrWhiteSpace(k.PrivateKeyPem) || !string.IsNullOrWhiteSpace(k.PrivateKeyPath)).ToList();

        Keys = configured.Count > 0
            ? configured.Select(k => Load(ReadPem(k, env), k.KeyId)).ToList()
            : [FallbackKey(opt, env)];

        PublicJwks = Keys.Select(ToPublicJwk).ToList();
    }

    /// <summary>All keys accepted for validation; the first one signs.</summary>
    public IReadOnlyList<RsaSecurityKey> Keys { get; }

    public RsaSecurityKey Active => Keys[0];

    public IReadOnlyList<JsonWebKey> PublicJwks { get; }

    private static RsaSecurityKey FallbackKey(JwtOptions opt, IHostEnvironment env)
    {
        if (env.IsEnvironment("Testing"))
            return Load(RSA.Create(MinKeySizeBits).ExportPkcs8PrivateKeyPem(), keyId: null);

        if (!env.IsDevelopment())
            throw new InvalidOperationException("Jwt:SigningKeys must be configured outside Development (RSA private key, PEM).");

        var path = Path.GetFullPath(Path.Combine(env.ContentRootPath, opt.DevKeyPath));
        if (!File.Exists(path))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, RSA.Create(MinKeySizeBits).ExportPkcs8PrivateKeyPem());
        }
        return Load(File.ReadAllText(path), keyId: "dev");
    }

    private static string ReadPem(SigningKeyOptions key, IHostEnvironment env) =>
        !string.IsNullOrWhiteSpace(key.PrivateKeyPem)
            ? key.PrivateKeyPem
            : File.ReadAllText(Path.GetFullPath(Path.Combine(env.ContentRootPath, key.PrivateKeyPath!)));

    private static RsaSecurityKey Load(string pem, string? keyId)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        if (rsa.KeySize < MinKeySizeBits)
            throw new InvalidOperationException($"JWT signing keys must be at least {MinKeySizeBits} bits (got {rsa.KeySize}).");

        return new RsaSecurityKey(rsa) { KeyId = string.IsNullOrWhiteSpace(keyId) ? Thumbprint(rsa) : keyId };
    }

    // Stable id derived from the public key, so the same key always gets the same kid.
    private static string Thumbprint(RSA rsa) =>
        Base64UrlEncoder.Encode(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()))[..16];

    private static JsonWebKey ToPublicJwk(RsaSecurityKey key)
    {
        var publicOnly = new RsaSecurityKey(key.Rsa.ExportParameters(includePrivateParameters: false)) { KeyId = key.KeyId };
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicOnly);
        jwk.Use = JsonWebKeyUseNames.Sig;
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        return jwk;
    }
}
