using System.Security.Cryptography;

namespace Identity.Application.Security;

/// <summary>TOTP (RFC 6238) with HMAC-SHA1, 30 s steps and 6 digits: what every authenticator app supports.</summary>
public static class Totp
{
    public const int Digits = 6;
    public const int StepSeconds = 30;
    public const int SecretBytes = 20;

    public static long TimeStep(DateTimeOffset time) => time.ToUnixTimeSeconds() / StepSeconds;

    public static string Compute(byte[] secret, long timeStep, int digits = Digits)
    {
        Span<byte> counter = stackalloc byte[8];
        for (var i = 7; i >= 0; i--, timeStep >>= 8) counter[i] = (byte)(timeStep & 0xFF);

        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, hash);

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        var otp = binary % (int)Math.Pow(10, digits);
        return otp.ToString().PadLeft(digits, '0');
    }

    /// <summary>
    /// Returns the time step the code belongs to (accepting one step of clock drift each way), or null.
    /// Callers must still reject a step that was already used (see IMfaRepository.TryAdvanceTimeStepAsync).
    /// </summary>
    public static long? Verify(byte[] secret, string code, DateTimeOffset now, int driftSteps = 1)
    {
        var normalized = code.Replace(" ", "", StringComparison.Ordinal).Trim();
        if (normalized.Length != Digits || !normalized.All(char.IsAsciiDigit)) return null;

        var current = TimeStep(now);
        long? match = null;
        for (var step = current - driftSteps; step <= current + driftSteps; step++)
        {
            // Check every candidate (no early exit) so timing does not reveal which step matched.
            if (CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(Compute(secret, step)), System.Text.Encoding.ASCII.GetBytes(normalized)))
                match = step;
        }
        return match;
    }

    public static string OtpAuthUri(string issuer, string account, byte[] secret) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}" +
        $"?secret={Base32.Encode(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
}

/// <summary>RFC 4648 base32 without padding, the format authenticator apps expect for secrets.</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var result = new System.Text.StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                result.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) result.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return result.ToString();
    }

    public static byte[] Decode(string text)
    {
        var clean = text.Replace(" ", "", StringComparison.Ordinal).TrimEnd('=').ToUpperInvariant();
        var output = new List<byte>(clean.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var c in clean)
        {
            var value = Alphabet.IndexOf(c);
            if (value < 0) throw new FormatException($"Invalid base32 character '{c}'");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        return output.ToArray();
    }
}
