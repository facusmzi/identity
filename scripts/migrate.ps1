# Builds the EF Core migration bundle and (unless -BundleOnly) applies it.
# This is the deploy step: outside Development the API does not migrate on startup and refuses to
# start against a database with pending migrations.
#
#   ./scripts/migrate.ps1                                   # local Podman database
#   ./scripts/migrate.ps1 -Connection "Host=...;..."        # any database
#   ./scripts/migrate.ps1 -BundleOnly                       # just produce artifacts/efbundle.exe
param(
    [string]$Connection = "Host=localhost;Port=5432;Database=identity;Username=identity;Password=identity",
    [switch]$BundleOnly
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    dotnet tool restore | Out-Null
    dotnet ef migrations bundle -p src/Identity.Infrastructure -s src/Identity.Api -o artifacts/efbundle.exe --force
    if ($LASTEXITCODE -ne 0) { throw "Bundle build failed" }

    if (-not $BundleOnly) {
        & ./artifacts/efbundle.exe --connection $Connection
        if ($LASTEXITCODE -ne 0) { throw "Migration failed" }
    }
}
finally {
    Pop-Location
}
