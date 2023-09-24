using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using WebApp1.Data;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.IdentityModel.Tokens;


// Ref: https://learn.microsoft.com/en-us/aspnet/core/data/ef-rp/intro?view=aspnetcore-7.0&tabs=visual-studio#create-the-web-app-project

var builder = WebApplication.CreateBuilder(args);
var hasDBConnectivity = false;

// Create a logger specifically for Program.cs
using var loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddSimpleConsole(i => i.ColorBehavior = LoggerColorBehavior.Disabled);
});

var logger = loggerFactory.CreateLogger<Program>();

// Add logging to the WebApplication
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

IEnumerable<string> initialScopes = builder.Configuration["DownstreamApi:Scopes"]?.Split(' ');

builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd")
    .EnableTokenAcquisitionToCallDownstreamApi(initialScopes)
    .AddDownstreamWebApi("DownstreamApi", builder.Configuration.GetSection("DownstreamApi"))
    .AddInMemoryTokenCaches();

// Add services to the container.
builder.Services.AddRazorPages().AddMvcOptions(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
}).AddMicrosoftIdentityUI();

try
{
    var connectionString = builder.Configuration.GetConnectionString("WebApp1EfDbContext-MI");
    if (connectionString.IsNullOrEmpty())
    {
       logger.LogError("Program.cs: Connection String 'WebApp1EfDbContext-MI' not found.");
       hasDBConnectivity = false;
    }
    else
    {
        builder.Services.AddDbContext<WebApp1EfDbContext>(options =>
            options.UseSqlServer(connectionString));
        hasDBConnectivity = true;
    }
}
catch (Exception e)
{
    logger.LogError(message: $"Program.cs: Unable to create Entity Framework DB context: {e}");
    hasDBConnectivity = false;
}

// Database exception filter
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Get access to HttpContext
builder.Services.AddHttpContextAccessor();

//   ===============   BUILDING THE APPLICATION   ===============
var app = builder.Build();
app.Logger.LogInformation("Program.cs: builder.Build() invoked");

app.UseAuthentication();
app.UseAuthorization();

// Comes from NuGet Microsoft.AspNetCore.HttpOverrides
app.UseForwardedHeaders();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.MapControllers().AllowAnonymous();
}
else
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
    app.MapControllers();
}

// Create database if not existing
if (hasDBConnectivity)
{
    app.Logger.LogInformation("Program.cs: Initialize Database with EF");
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;

        var context = services.GetRequiredService<WebApp1EfDbContext>();
        //context.Database.EnsureCreated();
        //DbInitializer.Initialize(context);
    }
}
else
{
    app.Logger.LogWarning("Program.cs: Initialize Database with EF");
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.MapRazorPages();
app.MapControllers();

app.Logger.LogInformation("Program.cs: app.Run() invoked");
app.Run();
