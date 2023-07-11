FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["Algorand2FAMultisig/Algorand2FAMultisig.csproj", "Algorand2FAMultisig/"]
RUN dotnet restore "Algorand2FAMultisig/Algorand2FAMultisig.csproj"
COPY . .
WORKDIR "/src/Algorand2FAMultisig"
RUN dotnet build "Algorand2FAMultisig.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Algorand2FAMultisig.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
COPY --from=build /src/version.json version.json
ENTRYPOINT ["dotnet", "Algorand2FAMultisig.dll"]