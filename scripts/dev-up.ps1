# Starts Postgres, Redis and Mailpit with plain podman (no compose provider needed).
# Usage: ./scripts/dev-up.ps1            start (or re-start) the containers
#        ./scripts/dev-up.ps1 -Down      stop and remove them (the Postgres volume is kept)
param([switch]$Down)

$containers = @(
    @{ Name = 'identity-postgres'; Args = @('-e', 'POSTGRES_DB=identity', '-e', 'POSTGRES_USER=identity', '-e', 'POSTGRES_PASSWORD=identity',
                                            '-p', '5432:5432', '-v', 'identity-pgdata:/var/lib/postgresql/data', 'docker.io/library/postgres:17-alpine') },
    @{ Name = 'identity-redis';    Args = @('-p', '6379:6379', 'docker.io/library/redis:7-alpine') },
    @{ Name = 'identity-mailpit';  Args = @('-p', '1025:1025', '-p', '8025:8025', 'docker.io/axllent/mailpit:latest') }
)

foreach ($c in $containers) {
    $exists = podman ps -a --format '{{.Names}}' | Where-Object { $_ -eq $c.Name }
    if ($Down) {
        if ($exists) { podman rm -f $c.Name | Out-Null; Write-Host "removed $($c.Name)" }
        continue
    }
    if ($exists) { podman start $c.Name | Out-Null }
    else { podman run -d --name $c.Name @($c.Args) | Out-Null }
    Write-Host "running $($c.Name)"
}

if (-not $Down) {
    Write-Host ""
    Write-Host "Postgres  localhost:5432 (identity/identity)"
    Write-Host "Redis     localhost:6379"
    Write-Host "Mailpit   http://localhost:8025  (SMTP on 1025)"
}
