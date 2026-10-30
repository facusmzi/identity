namespace Identity.Application.Abstractions;

/// <summary>Who is calling, as seen by the transport layer (HTTP in the API).</summary>
public interface IRequestContext
{
    string? IpAddress { get; }
}
