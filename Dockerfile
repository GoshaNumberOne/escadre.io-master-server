# Этап сборки .NET
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY MasterServer.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app

# Этап запуска
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "MasterServer.dll"]
