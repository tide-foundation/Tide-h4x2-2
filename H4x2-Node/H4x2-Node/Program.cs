// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

using H4x2_Node;
using H4x2_Node.Binders;

using Microsoft.AspNetCore.HttpOverrides;
using System.Numerics;
using H4x2_Node.Middleware;
using H4x2_TinySDK.Ed25519;
using H4x2_Node.Helpers;
using H4x2_Node.Services;

var builder = WebApplication.CreateBuilder(args);

var version = "Web-APP:3.0";
var isThrottled = true;
var key = new Key(BigInteger.Parse(args.Length == 0 ? Environment.GetEnvironmentVariable("TIDE_KEY") : args[0]));
var threshold = 3;
var maxAmount = 5;

builder.Services.AddControllers(options => options.ModelBinderProviders.Insert(0, new BinderProvider()));
builder.Services.AddSingleton(
    new Settings
    {
        Key = key,
        Threshold = threshold,
        MaxAmount = maxAmount
    });

builder.Services.AddLazyCache();

builder.Services.AddControllersWithViews();

var services = builder.Services;

services.AddDbContext<DataContext>();
services.AddScoped<IUserService, UserService>();


var app = builder.Build();


app.MapGet("/isThrottled", () => isThrottled);
app.MapGet("/public", () => key.Y.ToBase64());
app.MapGet("/version", () => version);
app.MapGet("/active", () => "true");

if (isThrottled)
{
    app.UseThrottling(); // neat
}

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseRouting();
app.UseCors(builder => {
    builder.AllowAnyOrigin();
    builder.AllowAnyMethod();
    builder.AllowAnyHeader();
});

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action}");


using (var scope = app.Services.CreateScope()) 
{
    var dataContext = scope.ServiceProvider.GetRequiredService<DataContext>();
    dataContext.Database.EnsureCreated();
}

app.Run();
