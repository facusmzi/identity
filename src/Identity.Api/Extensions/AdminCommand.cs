using System.Text.RegularExpressions;
using Identity.Application.Dtos;
using Identity.Infrastructure.Persistence;

namespace Identity.Api.Extensions;

/// <summary>
/// <c>seed-admin &lt;email&gt;</c>: creates a verified admin, or gives the Admin role to an existing user.
/// The password comes from IDENTITY_ADMIN_PASSWORD or the first line of stdin, never from arguments
/// (those end up in shell history and process listings).
/// </summary>
public static class AdminCommand
{
    public static async Task<int> SeedAdminAsync(IServiceProvider services, string[] args)
    {
        if (args.Length < 2 || !args[1].Contains('@'))
        {
            Console.Error.WriteLine("Usage: seed-admin <email>   (password via IDENTITY_ADMIN_PASSWORD or stdin)");
            return 2;
        }

        var password = Environment.GetEnvironmentVariable("IDENTITY_ADMIN_PASSWORD");
        if (string.IsNullOrEmpty(password) && Console.IsInputRedirected) password = Console.In.ReadLine();
        if (string.IsNullOrEmpty(password) || password.Length < 12 || !Regex.IsMatch(password, PasswordRules.Pattern))
        {
            Console.Error.WriteLine("The admin password must be 12-128 chars with a lowercase, an uppercase letter and a digit.");
            return 2;
        }

        var outcome = await DbInitializer.SeedAdminAsync(services, args[1], password);
        Console.WriteLine(outcome);
        return 0;
    }
}
