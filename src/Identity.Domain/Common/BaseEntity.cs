namespace Identity.Domain.Common;

public abstract class BaseEntity : ISoftDeletable
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? DeletedAt { get; set; }

    public bool IsDeleted => DeletedAt is not null;
}
