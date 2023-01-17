﻿using H4x2_Simulator.Helpers;
using H4x2_Simulator.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

var services = builder.Services;
services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
services.AddDbContext<DataContext>();
services.AddScoped<IUserService, UserService>();
services.AddScoped<IOrkService, OrkService>();



var app = builder.Build();

app.MapControllers();

app.Run();
