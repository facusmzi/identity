using Identity.Application.Abstractions;

namespace Identity.Api.Extensions;

/// <summary>Client IP after forwarded-headers processing (only trusted proxies can change it).</summary>
public sealed class HttpRequestContext(IHttpContextAccessor accessor) : IRequestContext
{
    public string? IpAddress => accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
}
