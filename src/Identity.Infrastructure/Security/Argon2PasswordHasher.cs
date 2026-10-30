using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Security;
using Identity.Application.Common;

namespace Identity.Infrastructure.Security;

public sealed class PasswordHashingOptions
{
    public const string Section = "PasswordHashing";

    // argon2id with 64 MiB, 3 iterations and 4 lanes (OWASP-recommended range).
    public int MemoryKb { get; set; } = 65536;
    public int Iterations { get; set; } = 3;
    public int Parallelism { get; set; } = 4;

    /// <summary>Hashes running at once. Peak memory is about MaxConcurrent * MemoryKb (8 * 64 MiB = 512 MiB).</summary>
    public int MaxConcurrent { get; set; } = 8;

    /// <summary>How long a request waits for a free slot before getting a 503.</summary>
    public int QueueTimeoutSeconds { get; set; } = 5;
}

/// <summary>Argon2id hashes in PHC format: $argon2id$v=19$m=..,t=..,p=..$salt$hash</summary>
public sealed class Argon2PasswordHasher : IPasswordHasher, IDisposable
{
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly PasswordHashingOptions _opt;
    private readonly SemaphoreSlim _slots;
    private readonly string _dummyHash;

    public Argon2PasswordHasher(IOptions<PasswordHashingOptions> options)
    {
        _opt = options.Value;
        _slots = new SemaphoreSlim(Math.Max(1, _opt.MaxConcurrent));
        _dummyHash = Encode(RandomNumberGenerator.GetBytes(SaltSize), RandomNumberGenerator.GetBytes(HashSize));
    }

    public async Task<string> HashAsync(string password, CancellationToken ct = default)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = await ComputeAsync(password, salt, _opt.MemoryKb, _opt.Iterations, _opt.Parallelism, HashSize, ct);
        return Encode(salt, hash);
    }

    public async Task<bool> VerifyAsync(string password, string encoded, CancellationToken ct = default)
    {
        var parts = encoded.Split('$');
        if (parts is not [_, "argon2id", "v=19", var paramPart, var saltPart, var hashPart]) return false;

        var parameters = paramPart.Split(',').Select(p => p.Split('=')).ToDictionary(p => p[0], p => int.Parse(p[1]));
        var salt = FromB64(saltPart);
        var expected = FromB64(hashPart);
        var actual = await ComputeAsync(password, salt, parameters["m"], parameters["t"], parameters["p"], expected.Length, ct);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public Task VerifyDummyAsync(string password, CancellationToken ct = default) => VerifyAsync(password, _dummyHash, ct);

    public void Dispose() => _slots.Dispose();

    private async Task<byte[]> ComputeAsync(
        string password, byte[] salt, int memoryKb, int iterations, int parallelism, int size, CancellationToken ct)
    {
        if (!await _slots.WaitAsync(TimeSpan.FromSeconds(_opt.QueueTimeoutSeconds), ct))
            throw new ServiceUnavailableException("Server busy, try again shortly", "BUSY", TimeSpan.FromSeconds(5));
        try
        {
            using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                MemorySize = memoryKb,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };
            return await argon.GetBytesAsync(size);
        }
        finally
        {
            _slots.Release();
        }
    }

    private string Encode(byte[] salt, byte[] hash) =>
        $"$argon2id$v=19$m={_opt.MemoryKb},t={_opt.Iterations},p={_opt.Parallelism}${ToB64(salt)}${ToB64(hash)}";

    private static string ToB64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static byte[] FromB64(string s) => Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
}
