using System.Text.RegularExpressions;

namespace Identity.Tests;

/// <summary>Rules that the compiler cannot enforce.</summary>
public sealed class ArchitectureTests
{
    private static readonly string SourceRoot = FindSourceRoot();

    /// <summary>
    /// ExecuteDelete bypasses SaveChanges, so it would physically delete soft-deletable rows without anyone
    /// noticing. It is allowed only inside retention purge methods (named Purge*).
    /// </summary>
    [Fact]
    public void ExecuteDelete_is_only_used_by_retention_purges()
    {
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(SourceRoot, "*.cs", SearchOption.AllDirectories)
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")))
        {
            var lines = File.ReadAllLines(file);
            string? currentMember = null;
            for (var i = 0; i < lines.Length; i++)
            {
                var member = Regex.Match(lines[i], @"\b(?:public|private|internal|protected)\b[^=(]*\s(\w+)\s*\(");
                if (member.Success) currentMember = member.Groups[1].Value;

                var isComment = lines[i].TrimStart().StartsWith("//");
                if (!isComment && lines[i].Contains("ExecuteDelete") && currentMember?.StartsWith("Purge") != true)
                    offenders.Add($"{Path.GetRelativePath(SourceRoot, file)}:{i + 1} (in {currentMember ?? "?"})");
            }
        }

        Assert.True(offenders.Count == 0, "ExecuteDelete outside a Purge* method:\n" + string.Join("\n", offenders));
    }

    [Fact]
    public void Application_layer_does_not_depend_on_infrastructure()
    {
        var references = typeof(Identity.Application.DependencyInjection).Assembly.GetReferencedAssemblies().Select(a => a.Name!);
        Assert.DoesNotContain(references, n => n.StartsWith("Identity.Infrastructure") || n.StartsWith("Microsoft.EntityFrameworkCore")
                                               || n.StartsWith("StackExchange.Redis") || n.StartsWith("Microsoft.AspNetCore"));
    }

    private static string FindSourceRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Identity.sln"))) dir = dir.Parent;
        return Path.Combine(dir?.FullName ?? throw new InvalidOperationException("Identity.sln not found"), "src");
    }
}
