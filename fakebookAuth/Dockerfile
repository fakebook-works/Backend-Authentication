FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS base
RUN apk add --no-cache krb5-libs
USER $APP_UID
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=1001
EXPOSE 1001

FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["fakebookAuth/fakebookAuth.csproj", "fakebookAuth/"]
RUN dotnet restore "fakebookAuth/fakebookAuth.csproj"
COPY . .
WORKDIR "/src/fakebookAuth"
RUN dotnet build "./fakebookAuth.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./fakebookAuth.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "fakebookAuth.dll"]
