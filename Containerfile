# Two images from one file:
#   podman build -t identity-api .                         (default target: runtime)
#   podman build -t identity-migrator --target migrator .
# Run the migrator as a deploy step before rolling out the API:
#   podman run --rm identity-migrator --connection "Host=...;Database=identity;Username=...;Password=..."

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Identity.sln dotnet-tools.json ./
COPY src/Identity.Domain/Identity.Domain.csproj src/Identity.Domain/
COPY src/Identity.Application/Identity.Application.csproj src/Identity.Application/
COPY src/Identity.Infrastructure/Identity.Infrastructure.csproj src/Identity.Infrastructure/
COPY src/Identity.Api/Identity.Api.csproj src/Identity.Api/
RUN dotnet restore src/Identity.Api/Identity.Api.csproj
COPY src/ src/
RUN dotnet publish src/Identity.Api/Identity.Api.csproj -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM build AS bundle
RUN dotnet tool restore \
 && dotnet ef migrations bundle -p src/Identity.Infrastructure -s src/Identity.Api \
      --configuration Release --self-contained -r linux-x64 -o /app/efbundle --force

FROM mcr.microsoft.com/dotnet/runtime-deps:11.0 AS migrator
WORKDIR /app
COPY --from=bundle /app/efbundle .
USER $APP_UID
ENTRYPOINT ["./efbundle"]

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_gcServer=0
EXPOSE 8080
# Non-root user shipped with the .NET images.
USER $APP_UID
ENTRYPOINT ["dotnet", "Identity.Api.dll"]
