# Identity

Servicio de autenticación en **.NET 10** con **Clean Architecture**: registro con verificación de email, login con
JWT + refresh tokens rotativos, sesiones, recuperación de contraseña, roles y borrado lógico.

## Capas

```
src/
  Identity.Domain          Entidades (User, Session, Role, UserRole), BaseEntity + ISoftDeletable. Sin dependencias.
  Identity.Application     Casos de uso (AuthService, SessionService, AdminService), DTOs, excepciones e
                           interfaces: IRepository<T>, IUserRepository, ISessionRepository, IRoleRepository,
                           IUnitOfWork, IPasswordHasher, ITokenService, IRefreshGraceStore, ILoginThrottle, IEmailSender.
  Identity.Infrastructure  EF Core + PostgreSQL, repositorios, Argon2id, JWT, Redis, SMTP (MailKit), migraciones.
  Identity.Api             Controllers, JWT bearer, rate limiting, proxies de confianza, errores como ProblemDetails.
tests/
  Identity.Tests           Tests de integración de la API completa (SQLite en memoria + fakes de Redis/SMTP).
```

Dependencias: `Api → Application ← Infrastructure` y `Application → Domain`. Application no conoce EF, Redis ni HTTP.

## Borrado lógico

- Todas las entidades heredan de `BaseEntity` (`Id`, `CreatedAt`, `UpdatedAt`, `DeletedAt`).
- `AppDbContext` aplica un **filtro global** `deleted_at IS NULL` a todas las entidades `ISoftDeletable`.
- `AuditAndSoftDeleteInterceptor` convierte **cualquier** `DELETE` (incluidos cascadas y huérfanos de colecciones)
  en un `UPDATE ... SET deleted_at = now()`. `repository.Remove(x)` nunca borra la fila.
- Los índices únicos (email, nombre de rol, user+rol) están **filtrados** por `deleted_at IS NULL`, así que un email
  borrado se puede volver a registrar.
- Para ver o restaurar borrados: `GetByIdIncludingDeletedAsync`, `GetWithRolesAsync(includeDeleted: true)`,
  `ListAsync(includeDeleted: true)` y `Restore(x)`.
- Revocar una sesión **no** es borrarla: se marca `revoked_at`.

## Sesiones y tokens

- Access token JWT (HS256, 15 min). En cada request se valida que la sesión siga viva y que el usuario no esté
  borrado; los roles se leen de la base, así que un cambio de rol aplica al instante.
- Refresh token opaco (`{sessionId}.{random}`, 30 días); en la base solo se guarda su SHA-256.
- La rotación es atómica (`UPDATE ... WHERE refresh_token_hash = old`). Durante una **ventana de gracia de 5 s**
  (Redis), reusar el token anterior devuelve el mismo par nuevo, para que los refresh concurrentes no fallen.
- **Detección de reuso**: un refresh token ya rotado que llega fuera de la ventana (de cualquier generación anterior)
  se asume robado y se revoca la sesión entera (`REFRESH_TOKEN_REUSED`).
- `change-password` revoca las demás sesiones; `reset-password` y borrar la cuenta revocan todas.

## Registro y verificación

- `register` responde siempre `202` con el mismo mensaje, exista o no el email, y siempre calcula Argon2.
  Los mails se mandan en segundo plano (`QueuedEmailSender`), así el tiempo de respuesta no depende del envío.
- `verify-email` pide el **código y la contraseña** elegida al registrarse. Volver a registrar una cuenta sin
  verificar reemplaza la contraseña y manda un código nuevo. Así, aunque alguien registre primero el email de otra
  persona, nunca puede terminar dueño de una cuenta verificada con ese email.
- `resend-verification` y `forgot-password` responden siempre lo mismo.
- Por hora y por cuenta: máximo 5 códigos enviados y 10 intentos fallidos (`429 TOO_MANY_ATTEMPTS`). Pedir un código
  nuevo no resetea los intentos.
- **Recuperación de contraseña** con token de un solo uso (hasheado, 30 min). El reset marca el email como verificado.
  Con `Auth:PasswordResetUrl` el mail lleva un link `?email=..&token=..` a tu frontend.

## Protecciones

- **Argon2 acotado**: como mucho `PasswordHashing:MaxConcurrent` hashes a la vez (8 × 64 MiB ≈ 512 MiB). Sin lugar en
  `QueueTimeoutSeconds`, responde `503` con `Retry-After` en vez de agotar la RAM. Todas las contraseñas tienen máximo
  128 caracteres.
- **Bloqueo por cuenta** (Redis, compartido entre instancias): 10 logins fallidos en 15 min bloquean ese email por
  15 min (`429 ACCOUNT_LOCKED`), vengan de las IPs que vengan. Aplica también a emails inexistentes.
- **Rate limit por IP** (en memoria, por instancia): 5/min en register, resend y forgot; 10/min en login, refresh,
  verify y reset.
- **Arranque seguro**: fuera de `Development`/`Testing`, la API no arranca si `Jwt:Secret` parece de desarrollo,
  si no hay SMTP configurado o si `Seed:AdminPassword` es débil.
- **Proxies**: `X-Forwarded-For` solo se acepta de los proxies en `ForwardedHeaders:KnownProxies` o `KnownNetworks`
  (por ejemplo `["10.0.0.0/8"]`). Sin configurarlos se ignora, así nadie puede falsificar su IP. Si la API corre
  detrás de nginx o de un load balancer, configuralos: si no, todos los usuarios comparten el límite por IP del proxy.
- Las operaciones de varios pasos (cambiar/resetear contraseña, borrar cuenta o usuario) corren en una transacción.

### Riesgos conocidos

- El bloqueo por cuenta permite que un tercero deje sin login a otra cuenta durante 15 min.
- Registrar un email nuevo tarda unos ms más que uno existente (el INSERT). Con muchas mediciones se podría inferir
  si un email está registrado; el rate limit lo hace lento.
- Tras 10 intentos fallidos de verificación, el `429` revela que hay una cuenta pendiente con ese email.
- Los mails en cola se pierden si el proceso se cae antes de enviarlos (el usuario puede pedir otro).
- HS256: cualquier servicio que valide tokens necesita el secreto, y con él también podría firmarlos. Si otras apps
  van a validar tokens, conviene pasar a RS256/EdDSA con un endpoint JWKS.

## Levantar en local (Podman)

```powershell
./scripts/dev-up.ps1                                    # Postgres, Redis y Mailpit
dotnet run --project src/Identity.Api --launch-profile http
```

- API: http://localhost:5205 · Docs (Scalar): http://localhost:5205/scalar
- Mails: http://localhost:8025 (Mailpit)
- Admin sembrado en Development: `admin@identity.local` / `Admin12345` (`Seed` en `appsettings.Development.json`)
- Las migraciones se aplican solas al arrancar. `./scripts/dev-up.ps1 -Down` baja los contenedores.
- Si instalás `podman-compose`, también sirve `podman compose up -d` con `compose.yaml`.

Para producción: definí `Jwt__Secret` (32+ caracteres aleatorios), `ConnectionStrings__Postgres`,
`ConnectionStrings__Redis` y `Smtp__*` por variables de entorno, y dejá `Seed` vacío o con una contraseña fuerte.

## Endpoints

| Método | Ruta | Auth |
| --- | --- | --- |
| POST | `/auth/register` · `/auth/verify-email` · `/auth/resend-verification` | — |
| POST | `/auth/login` · `/auth/refresh` | — |
| POST | `/auth/forgot-password` · `/auth/reset-password` | — |
| POST | `/auth/logout` · `/auth/logout-all` · `/auth/change-password` | Bearer |
| GET / DELETE | `/auth/me` (DELETE = borrado lógico de tu cuenta, pide contraseña) | Bearer |
| GET / DELETE | `/sessions` · `/sessions/{id}` | Bearer |
| GET | `/admin/users?page=&pageSize=&includeDeleted=` · `/admin/users/{id}` · `/admin/roles` | Admin |
| DELETE / POST | `/admin/users/{id}` · `/admin/users/{id}/restore` | Admin |
| POST / DELETE | `/admin/users/{id}/roles` · `/admin/users/{id}/roles/{role}` | Admin |

Ejemplos listos para usar en [`src/Identity.Api/Identity.Api.http`](src/Identity.Api/Identity.Api.http).

## Migraciones

```powershell
dotnet tool restore
dotnet ef migrations add <Nombre> -p src/Identity.Infrastructure -s src/Identity.Api -o Persistence/Migrations
```

## Tests

```powershell
dotnet test
```
