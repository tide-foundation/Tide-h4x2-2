#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["H4x2-Node/H4x2-Node.csproj", "H4x2-Node/"]
RUN dotnet restore "H4x2-Node/H4x2-Node.csproj"
COPY . .
WORKDIR "/src/H4x2-Node"
RUN dotnet build "H4x2-Node.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "H4x2-Node.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /ork
RUN mkdir db
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "H4x2-Node.dll"]