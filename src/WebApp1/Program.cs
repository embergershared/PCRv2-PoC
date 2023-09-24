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
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using WebApp1.Data;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.IdentityModel.Tokens;


// Ref: https://learn.microsoft.com/en-us/aspnet/core/data/ef-rp/intro?view=aspnetcore-7.0&tabs=visual-studio#create-the-web-app-project

#region Program.cs specific logger instance
using var loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddSimpleConsole(i => i.ColorBehavior = LoggerColorBehavior.Disabled);
});
var logger = loggerFactory.CreateLogger<Program>();
#endregion

// Properties
var hasDbConnectivity = false;

#region   ===============   CREATING THE APP BUILDER   ===============
var builder = WebApplication.CreateBuilder(args);

// Add logging to the WebApplication
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Add Microsoft Identity Web Authentication
IEnumerable<string> initialScopes = builder.Configuration["DownstreamApi:Scopes"]?.Split(' ');
builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd")
    .EnableTokenAcquisitionToCallDownstreamApi(initialScopes)
    .AddDownstreamWebApi("DownstreamApi", builder.Configuration.GetSection("DownstreamApi"))
    .AddInMemoryTokenCaches();
    // Consider caching the token to scale: https://aka.ms/msal-net-cca-token-cache-serialization

// Add Razor Pages, MVC controller and Microsoft Identity UI
builder.Services
    .AddRazorPages()
    .AddRazorPagesOptions(options =>
    {
        // options.Conventions.AuthorizePage("/Contact");
        // options.Conventions.AuthorizeFolder("/Private");
        options.Conventions.AllowAnonymousToPage("/Index");
        // options.Conventions.AllowAnonymousToFolder("/Private/PublicPages");
    })
    .AddMvcOptions(options =>
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
        options.Filters.Add(new AuthorizeFilter(policy));
    })
    .AddMicrosoftIdentityUI();

// Entity Framework DB Context to SQL Server
try
{
    var connectionString = builder.Configuration.GetConnectionString("WebApp1EfDbContext-MI");
    if (connectionString.IsNullOrEmpty())
    {
       logger.LogError($"Program.cs: Value for ConnectionString: 'WebApp1EfDbContext-MI' not found.");
       hasDbConnectivity = false;
    }
    else
    {
        builder.Services.AddDbContext<WebApp1EfDbContext>(options =>
            options.UseSqlServer(connectionString));

        // Database exception filter
        builder.Services.AddDatabaseDeveloperPageExceptionFilter();

        hasDbConnectivity = true;
    }
}
catch (Exception e)
{
    logger.LogError($"Program.cs: Unable to create Entity Framework DB context: {e}");
    hasDbConnectivity = false;
}

// Get access to HttpContext
builder.Services.AddHttpContextAccessor();
#endregion

#region   ===============   BUILDING THEN RUN THE APP  ===============
var app = builder.Build();
app.Logger.LogInformation("Program.cs: builder.Build() invoked");

// Activate Authentication and Authorization
app.UseAuthentication();
app.UseAuthorization();

// Comes from NuGet Microsoft.AspNetCore.HttpOverrides
app.UseForwardedHeaders();

// Configure the HTTP request pipeline if in Dev environment
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
if (hasDbConnectivity)
{
    app.Logger.LogInformation("Program.cs: Initialize Database with EF");
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;

    var context = services.GetRequiredService<WebApp1EfDbContext>();
    context.Database.EnsureCreated();
    DbInitializer.Initialize(context);
}
else
{
    app.Logger.LogWarning("Program.cs: Launching Web App without Database connectivity");
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.MapRazorPages();

Config.App["DbIsAccessible"] = hasDbConnectivity.ToString();

app.Logger.LogInformation("Program.cs: app.Run() invoked");
app.Run();
#endregion