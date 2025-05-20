# Этап сборки
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Копируем файлы проекта
COPY MasterServer.csproj .
RUN dotnet restore

# Копируем всё остальное и собираем
COPY . .
RUN dotnet publish -c Release -o /app

# Этап запуска
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Открываем порты
EXPOSE 80
EXPOSE 443

ENTRYPOINT ["dotnet", "escadre.io-master-server.dll"]
