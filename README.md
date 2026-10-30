# Identity

Servicio de autenticación en **.NET 10** con **Clean Architecture**: registro con verificación de email, login con
JWT (RS256) + refresh tokens rotativos, sesiones, recuperación de contraseña, roles, auditoría y borrado lógico.

## Capas

```
src/
  Identity.Domain          Entidades (User, Session, Role, UserRole, AuditEntry), BaseEntity + ISoftDeletable.
  Identity.Application     Casos de uso (AuthService, SessionService, AdminService, AuditTrail), DTOs, excepciones e
                           interfaces: repositorios, IUnitOfWork, IPasswordHasher, ITokenService, IRefreshGraceStore,
                           ILoginThrottle, IEmailOutbox, IRequestContext.
  Identity.Infrastructure  EF Core + PostgreSQL, repositorios, Argon2id, JWT/JWKS, Redis, outbox de mails (MailKit),
                           limpieza por retención, migraciones.
  Identity.Api             Controllers, JWT bearer, rate limiting, proxies, CORS, health checks, ProblemDetails.
tests/
  Identity.Tests           Integración de la API completa: SQLite + fakes (rápidos) y Postgres + Redis reales
                           con Testcontainers (carpeta Postgres/).
```

Dependencias: `Api → Application ← Infrastructure` y `Application → Domain`. Application no conoce EF, Redis ni HTTP
(lo verifica `ArchitectureTests`).

## Borrado lógico

- Todas las entidades de negocio heredan de `BaseEntity` (`Id`, `CreatedAt`, `UpdatedAt`, `DeletedAt`).
- `AppDbContext` aplica un **filtro global** `deleted_at IS NULL` a todas las entidades `ISoftDeletable`.
- `AuditAndSoftDeleteInterceptor` convierte **cualquier** `DELETE` (incluidos cascadas y huérfanos de colecciones)
  en un `UPDATE ... SET deleted_at = now()`. `repository.Remove(x)` nunca borra la fila.
- Los índices únicos (email, nombre de rol, user+rol) están **filtrados** por `deleted_at IS NULL`, así que un email
  borrado se puede volver a registrar.
- `ExecuteDelete` se saltea el interceptor y borraría de verdad: solo se permite en los métodos de purga por retención
  (`Purge*`). `ArchitectureTests` falla si aparece en cualquier otro lado.
- Revocar una sesión **no** es borrarla: se marca `revoked_at`.

## Sesiones y tokens

- Access token **JWT RS256** (15 min). En cada request se valida que la sesión siga viva y que el usuario no esté
  borrado, y se cargan sus roles.
- **Caché de sesiones** (Redis, `Auth:SessionCacheSeconds`, 30 s; 0 la apaga): esa validación sale de Redis en vez de
  la base. Igual, revocar una sesión, cambiar roles o la contraseña, o borrar el usuario aplica **en el request
  siguiente**: cada uno de esos caminos incrementa un número de generación por usuario después del commit, y una
  entrada solo sirve si se escribió con la generación vigente (así una lectura vieja que se escribe tarde nunca se
  usa). Si Redis no está disponible se valida contra la base sin esperar timeouts; si una invalidación se pierde por
  una caída de Redis, lo cacheado vive como mucho esos 30 s.
- Las claves públicas se publican en `/.well-known/jwks.json` (y `/.well-known/openid-configuration`). Otros servicios
  validan los tokens solos, sin poder firmarlos:
  `AddJwtBearer(o => { o.Authority = "https://identity.tu-dominio.com"; o.Audience = "identity"; })`
  (para eso `Jwt:Issuer` tiene que ser esa URL pública).
- **Rotación de claves**: `Jwt:SigningKeys` es una lista; la primera firma y todas se publican y aceptan. Para rotar,
  agregá la nueva primera, esperá a que venzan los tokens viejos (15 min) y quitá la anterior.
- Refresh token opaco (`{sessionId}.{random}`, 30 días); en la base solo se guarda su SHA-256. La rotación es atómica
  y una **ventana de gracia de 5 s** (Redis) cubre los refresh concurrentes.
- **Detección de reuso**: un refresh token ya rotado que llega fuera de la ventana se asume robado y se revoca la
  sesión entera (`REFRESH_TOKEN_REUSED`, queda en la auditoría).
- Las sesiones se leen sin tracking y solo se modifican con UPDATEs atómicos del repositorio (nunca entidades
  trackeadas + `SaveChanges`), para que una copia vieja en memoria no pise una revocación concurrente.

## Registro, verificación y mails

- `register` responde siempre `202`, exista o no el email, y siempre calcula Argon2. Dos registros simultáneos del
  mismo email no dan error: la violación del índice único se traduce y se responde igual.
- `verify-email` pide el **código y la contraseña**. Volver a registrar una cuenta sin verificar reemplaza la
  contraseña, así nadie puede quedarse con una cuenta verificada a nombre de un email ajeno.
- Por hora y por cuenta: máximo 5 códigos y 10 intentos fallidos. Pedir un código nuevo no resetea los intentos.
- **Outbox transaccional**: los mails se guardan en `outbox_emails` en la misma transacción que el cambio que los
  causa y los entrega un proceso en segundo plano, con reintentos (backoff exponencial, hasta 8) y bloqueo por fila
  para que varias instancias no manden dos veces el mismo. El código/token se borra de la tabla apenas se entrega.
- Recuperación de contraseña con token de un solo uso (hasheado, 30 min). El reset marca el email como verificado.

## Administración y auditoría

- Roles `Admin` y `User`. Un admin no puede quitarse su propio rol, para borrar a otro admin primero hay que quitarle
  el rol, y nunca se puede quedar el sistema sin admins (`LAST_ADMIN`).
- `audit_log` registra, en la misma transacción que la acción: logins (ok y fallidos), bloqueos, verificación,
  cambio y reset de contraseña, reuso de refresh token, borrado de cuenta y todas las acciones de admin (con quién la
  hizo, a quién y desde qué IP). Nunca guarda contraseñas ni tokens. Se consulta en `GET /admin/audit`.

## Protecciones

- **Argon2 acotado**: como mucho `PasswordHashing:MaxConcurrent` hashes a la vez; si no hay lugar responde `503`.
  Todas las contraseñas tienen máximo 128 caracteres.
- **Bloqueo por cuenta** (Redis): 10 logins fallidos en 15 min bloquean ese email 15 min (`429 ACCOUNT_LOCKED`).
- **Rate limit por IP** (en memoria, por instancia): 5/min en register, resend y forgot; 10/min en el resto.
- **Arranque seguro**: fuera de `Development`/`Testing` la API no arranca sin clave de firma, sin SMTP o con un admin
  sembrado débil, y carga la clave al iniciar (una clave ilegible frena el arranque, no cada request).
- **Proxies**: `X-Forwarded-For` solo se acepta de `ForwardedHeaders:KnownProxies` / `KnownNetworks`.
- **CORS** cerrado salvo los orígenes de `Cors:AllowedOrigins`.

### Riesgos conocidos

- El bloqueo por cuenta permite que un tercero deje sin login a otra cuenta durante 15 min.
- Registrar un email nuevo tarda unos ms más que uno existente (el INSERT); con muchas mediciones se podría inferir.
- Tras 10 intentos fallidos de verificación, el `429` revela que hay una cuenta pendiente con ese email.
- El outbox guarda el código/token en claro hasta que se entrega (segundos, salvo que el SMTP esté caído).
- El rate limit por IP no se comparte entre instancias (el bloqueo por cuenta sí).

## Retención

Un proceso en segundo plano (`Retention:*`, cada hora) borra físicamente: sesiones terminadas hace más de 30 días,
mails del outbox entregados o abandonados hace más de 7 días y auditoría de más de 365 días.

## Levantar en local (Podman)

```powershell
./scripts/dev-up.ps1                                    # Postgres, Redis y Mailpit
dotnet run --project src/Identity.Api --launch-profile http
```

- API: http://localhost:5205 · Docs (Scalar): http://localhost:5205/scalar · Mails: http://localhost:8025 (Mailpit)
- Admin sembrado en Development: `admin@identity.local` / `Admin12345`.
- En Development las migraciones se aplican solas y la clave de firma se genera en `src/Identity.Api/.keys/`
  (ignorada por git).
- Health: `/health/live` (proceso vivo) y `/health/ready` (Postgres y Redis responden).

## Producción

```powershell
podman build -t identity-api .                          # API (usuario no-root, puerto 8080)
podman build -t identity-migrator --target migrator .   # bundle de migraciones
```

1. **Migraciones como paso del deploy**: `podman run --rm identity-migrator --connection "<cadena>"` (o
   `./scripts/migrate.ps1 -Connection "<cadena>"`). La API no migra sola fuera de Development y se niega a arrancar
   si a la base le faltan migraciones.
2. **Clave de firma**: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out jwt.pem`, montala como
   secreto y pasá `Jwt__SigningKeys__0__PrivateKeyPath=/run/secrets/jwt.pem` (y opcionalmente `__KeyId`).
3. Variables: `ConnectionStrings__Postgres`, `ConnectionStrings__Redis`, `Smtp__*`, `Jwt__Issuer` (URL pública),
   `Cors__AllowedOrigins__0`, `ForwardedHeaders__KnownNetworks__0` si hay proxy.
4. Los logs salen en JSON (una línea por evento, con request id y trace id).

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
| GET | `/admin/audit?userId=&action=&page=&pageSize=` | Admin |
| DELETE / POST | `/admin/users/{id}` · `/admin/users/{id}/restore` | Admin |
| POST / DELETE | `/admin/users/{id}/roles` · `/admin/users/{id}/roles/{role}` | Admin |
| GET | `/.well-known/jwks.json` · `/.well-known/openid-configuration` · `/health/live` · `/health/ready` | — |

Ejemplos listos para usar en [`src/Identity.Api/Identity.Api.http`](src/Identity.Api/Identity.Api.http).

## Migraciones

```powershell
dotnet tool restore
dotnet ef migrations add <Nombre> -p src/Identity.Infrastructure -s src/Identity.Api -o Persistence/Migrations
```

El CI falla si el modelo cambió sin una migración (`dotnet ef migrations has-pending-model-changes`).

## Tests

```powershell
dotnet test                                  # todo
dotnet test --filter "Category!=Postgres"    # solo los rápidos, sin contenedores
```

Los tests de `Postgres/` levantan Postgres y Redis con Testcontainers, que usa Docker o la API compatible de Podman.
Sin un runtime de contenedores se saltean en local; en CI (`CI=true`) fallan.

## CI

`.github/workflows/ci.yml`: build, chequeo de migraciones, todos los tests (incluidos los de Postgres) y build de
las dos imágenes.
