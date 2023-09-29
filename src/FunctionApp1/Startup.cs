using System;
using FunctionApp1;
using FunctionApp1.EfCore;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

[assembly: FunctionsStartup(typeof(StartUp))]

namespace FunctionApp1
{
  public class StartUp : FunctionsStartup
  {
    public override void Configure(IFunctionsHostBuilder builder)
    {
      var connectionString = Environment.GetEnvironmentVariable("FuncApp1EfDbContext-AS") ??
                              throw new InvalidOperationException("Startup(): Connection String 'FuncApp1EfDbContext-AS' not found.");

      builder.Services.AddDbContext<FuncApp1EfDbContext>(
          options => options.UseSqlServer(connectionString));
    }
  }
}