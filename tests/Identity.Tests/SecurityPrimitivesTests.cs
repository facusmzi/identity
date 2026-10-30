using System.Net;
using System.Text;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Security;
using Identity.Application.Security;
using Identity.Infrastructure.Security;

namespace Identity.Tests;

/// <summary>Unit tests of the crypto building blocks, against published test vectors where they exist.</summary>
public sealed class SecurityPrimitivesTests
{
    // RFC 6238 appendix B, SHA-1 secret = ASCII "12345678901234567890", 8 digits.
    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(20000000000L, "65353130")]
    public void Totp_matches_rfc6238_vectors(long unixTime, string expected)
    {
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        Assert.Equal(expected, Totp.Compute(secret, unixTime / 30, digits: 8));
    }

    [Fact]
    public void Totp_accepts_one_step_of_drift_and_rejects_more()
    {
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var step = Totp.TimeStep(now);

        Assert.Equal(step, Totp.Verify(secret, Totp.Compute(secret, step), now));
        Assert.Equal(step - 1, Totp.Verify(secret, Totp.Compute(secret, step - 1), now));
        Assert.Equal(step + 1, Totp.Verify(secret, Totp.Compute(secret, step + 1), now));
        Assert.Null(Totp.Verify(secret, Totp.Compute(secret, step + 2), now));
        Assert.Null(Totp.Verify(secret, "12345", now));
        Assert.Null(Totp.Verify(secret, "abcdef", now));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("foobar", "MZXW6YTBOI")] // RFC 4648 §10 (without padding)
    public void Base32_matches_rfc4648(string text, string encoded)
    {
        Assert.Equal(encoded, Base32.Encode(Encoding.ASCII.GetBytes(text)));
        Assert.Equal(text, Encoding.ASCII.GetString(Base32.Decode(encoded)));
    }

    [Fact]
    public void Encrypted_secrets_are_bound_to_their_owner_and_tamper_evident()
    {
        var protector = new AesGcmSecretProtector(Options.Create(new SecretEncryptionOptions()), new TestEnv("Testing"));
        var secret = Encoding.ASCII.GetBytes("my-totp-secret");

        var sealedValue = protector.Protect(secret, "user-a");
        Assert.StartsWith("v1.", sealedValue);
        Assert.DoesNotContain("my-totp-secret", sealedValue);
        Assert.Equal(secret, protector.Unprotect(sealedValue, "user-a"));

        Assert.Null(protector.Unprotect(sealedValue, "user-b"));                 // copied to another user's row
        Assert.Null(protector.Unprotect(sealedValue[..^2] + "AA", "user-a"));      // tampered
        Assert.Null(protector.Unprotect("v1.other-key." + sealedValue.Split('.')[2], "user-a")); // unknown key
    }

    [Fact]
    public void Encryption_key_is_required_outside_development() =>
        Assert.Throws<InvalidOperationException>(() =>
            new AesGcmSecretProtector(Options.Create(new SecretEncryptionOptions()), new TestEnv("Production")));

    [Fact]
    public async Task Hibp_only_sends_the_hash_prefix_and_asks_for_padding()
    {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n"),
        });
        var checker = Checker(handler);

        Assert.Equal(BreachCheckStatus.Breached, await checker.CheckAsync("password"));
        Assert.Equal("/range/5BAA6", handler.LastRequest!.RequestUri!.AbsolutePath);
        Assert.Equal("true", handler.LastRequest.Headers.GetValues("Add-Padding").Single());
        Assert.DoesNotContain("1E4C9B93", handler.LastRequest.RequestUri.ToString());
    }

    [Fact]
    public async Task Hibp_padding_entries_and_unknown_suffixes_are_not_breaches()
    {
        // The padding entry has the right suffix but count 0.
        var padded = Checker(new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\r\n"),
        }));
        Assert.Equal(BreachCheckStatus.NotBreached, await padded.CheckAsync("password"));

        var down = Checker(new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        Assert.Equal(BreachCheckStatus.Unavailable, await down.CheckAsync("password"));

        var broken = Checker(new FakeHandler(_ => throw new HttpRequestException("no network")));
        Assert.Equal(BreachCheckStatus.Unavailable, await broken.CheckAsync("password"));
    }

    private static HibpPasswordBreachChecker Checker(FakeHandler handler) =>
        new(new HttpClient(handler) { BaseAddress = new Uri("https://hibp.test/") },
            Options.Create(new HibpClientOptions()), NullLogger<HibpPasswordBreachChecker>.Instance);

    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastRequest = request;
            return Task.FromResult(respond(request));
        }
    }

    private sealed class TestEnv(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "Identity.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
