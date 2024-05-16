# Usa la imagen base que contiene el runtime de .NET Core
FROM mcr.microsoft.com/dotnet/sdk:8.0-jammy AS base
WORKDIR /app

# Copia los archivos de la aplicación
FROM mcr.microsoft.com/dotnet/sdk:8.0-jammy AS build
WORKDIR /src
COPY . .

ENTRYPOINT ["dotnet", "run"]