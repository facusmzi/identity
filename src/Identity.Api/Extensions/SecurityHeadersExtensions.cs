namespace Identity.Api.Extensions;

public static class SecurityHeadersExtensions
{
    /// <summary>
    /// Headers for a JSON API that is never meant to be framed, sniffed or cached:
    /// <list type="bullet">
    /// <item><c>Cache-Control: no-store</c> unless the endpoint set its own policy (the JWKS is cacheable): responses
    /// carry tokens and personal data, no proxy or browser cache should keep them.</item>
    /// <item>A CSP that allows nothing (relaxed only for the API docs UI in Development).</item>
    /// <item>nosniff, no framing, no referrer, no powerful browser features.</item>
    /// </list>
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app, IHostEnvironment env) =>
        app.Use(async (context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers.XContentTypeOptions = "nosniff";
                headers.XFrameOptions = "DENY";
                headers["Referrer-Policy"] = "no-referrer";
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
                headers["Cross-Origin-Opener-Policy"] = "same-origin";

                var isDocs = env.IsDevelopment()
                             && (context.Request.Path.StartsWithSegments("/scalar") || context.Request.Path.StartsWithSegments("/openapi"));
                if (!isDocs) headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";

                if (string.IsNullOrEmpty(headers.CacheControl)) headers.CacheControl = "no-store";
                return Task.CompletedTask;
            });
            await next();
        });

    /// <summary>HSTS outside Development (sent only on HTTPS, i.e. once the proxy forwarded the original scheme).</summary>
    public static IServiceCollection AddStrictTransportSecurity(this IServiceCollection services) =>
        services.AddHsts(o =>
        {
            o.MaxAge = TimeSpan.FromDays(365);
            o.IncludeSubDomains = true;
        });
}
