namespace Identity.Domain.Enums;

public enum LoginMethod
{
    Email = 0,

    /// <summary>Password plus a second factor (TOTP or recovery code).</summary>
    EmailMfa = 1,
}
