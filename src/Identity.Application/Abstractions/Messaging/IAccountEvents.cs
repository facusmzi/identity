namespace Identity.Application.Abstractions.Messaging;

/// <summary>
/// Account events delivered to the clients that configured a WebhookUrl (e.g. the store anonymizes orders when a
/// user is deleted). Like the email outbox: staged in the same transaction as the change (call before SaveChanges),
/// delivered later with retries, so there is no event for a change that was rolled back and none is lost.
/// </summary>
public interface IAccountEvents
{
    void Publish(string type, Guid userId);
}

public static class AccountEventTypes
{
    public const string UserDeleted = "user.deleted";
    public const string UserRestored = "user.restored";
    public const string UserLocked = "user.locked";
    public const string UserUnlocked = "user.unlocked";
}
