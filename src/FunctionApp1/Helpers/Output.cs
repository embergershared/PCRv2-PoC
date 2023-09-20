using Microsoft.Extensions.Logging;
using System;

namespace FunctionApp1.Helpers
{
    internal static class Output {

        internal static void Log(ILogger logger, string content)
        {
            Console.WriteLine($"[Console] {content}");
            logger.LogInformation($"[Log] {content}");
        }
    }
}
