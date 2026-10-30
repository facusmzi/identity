namespace Identity.Domain.Common;

/// <summary>
/// Entities implementing this are never physically removed: a delete sets
/// <see cref="DeletedAt"/> and they are hidden by a global query filter.
/// </summary>
public interface ISoftDeletable
{
    DateTime? DeletedAt { get; set; }
}
