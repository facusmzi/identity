using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Identity.Application.Abstractions.Messaging;

namespace Identity.Infrastructure.Messaging;

/// <summary>
/// Hands emails to a background worker instead of sending them inside the request. Besides keeping SMTP latency
/// out of the response, it makes "email sent" and "nothing sent" take the same time, so response timing does not
/// reveal whether an account exists (register, resend-verification, forgot-password).
/// </summary>
public sealed class QueuedEmailSender(EmailQueue queue) : IEmailSender
{
    public Task SendVerificationCodeAsync(string to, string code, CancellationToken ct = default) =>
        queue.EnqueueAsync((sender, token) => sender.SendVerificationCodeAsync(to, code, token), ct);

    public Task SendPasswordResetAsync(string to, string token, string? link, CancellationToken ct = default) =>
        queue.EnqueueAsync((sender, t) => sender.SendPasswordResetAsync(to, token, link, t), ct);
}

public sealed class EmailQueue
{
    private readonly Channel<Func<IEmailSender, CancellationToken, Task>> _channel =
        Channel.CreateBounded<Func<IEmailSender, CancellationToken, Task>>(new BoundedChannelOptions(1000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
        });

    public Task EnqueueAsync(Func<IEmailSender, CancellationToken, Task> send, CancellationToken ct) =>
        _channel.Writer.WriteAsync(send, ct).AsTask();

    public IAsyncEnumerable<Func<IEmailSender, CancellationToken, Task>> ReadAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}

/// <summary>Sends queued emails through the real transport (SMTP, or the log in development).</summary>
public sealed class EmailDispatcher(EmailQueue queue, EmailTransport transport, ILogger<EmailDispatcher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var send in queue.ReadAllAsync(stoppingToken))
        {
            try
            {
                await send(transport.Sender, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Failed to send email");
            }
        }
    }
}

/// <summary>Wraps the concrete sender so it is not registered as IEmailSender itself.</summary>
public sealed record EmailTransport(IEmailSender Sender);
