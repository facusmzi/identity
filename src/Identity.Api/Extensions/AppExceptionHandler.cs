using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Identity.Application.Common;

namespace Identity.Api.Extensions;

/// <summary>Maps Application exceptions to RFC 7807 problem details.</summary>
public sealed class AppExceptionHandler(IProblemDetailsService problemDetails) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken ct)
    {
        if (exception is not AppException app) return false;

        var status = app switch
        {
            BadRequestException => StatusCodes.Status400BadRequest,
            UnauthorizedException => StatusCodes.Status401Unauthorized,
            ForbiddenException => StatusCodes.Status403Forbidden,
            NotFoundException => StatusCodes.Status404NotFound,
            ConflictException => StatusCodes.Status409Conflict,
            TooManyRequestsException => StatusCodes.Status429TooManyRequests,
            ServiceUnavailableException => StatusCodes.Status503ServiceUnavailable,
            _ => StatusCodes.Status400BadRequest,
        };

        var retryAfter = app switch
        {
            TooManyRequestsException e => e.RetryAfter,
            ServiceUnavailableException e => e.RetryAfter,
            _ => null,
        };
        if (retryAfter is { } wait)
            httpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(Math.Max(wait.TotalSeconds, 1))).ToString();

        if (app is UnauthorizedException { Code: "INVALID_CLIENT" })
            httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"identity\"";

        httpContext.Response.StatusCode = status;
        var problem = new ProblemDetails { Status = status, Title = app.Message };
        if (app.Code is not null) problem.Extensions["code"] = app.Code;

        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problem,
            Exception = exception,
        });
    }
}
