namespace Identity.Domain.Enums;

/// <summary>Why a session ended early. Stored with the session for investigations and to explain a logout.</summary>
public enum RevocationReason
{
    Logout = 0,
    LogoutAll = 1,
    RevokedByUser = 2,
    PasswordChanged = 3,
    PasswordReset = 4,
    MfaChanged = 5,
    AccountDeleted = 6,
    RefreshTokenReused = 7,
    AdminRevoked = 8,
    AdminLocked = 9,
    AdminDeleted = 10,
}
