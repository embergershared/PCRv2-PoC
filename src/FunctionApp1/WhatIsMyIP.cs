using System;
using System.Net.Http;
using System.Threading.Tasks;
using FunctionApp1.Helpers;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;

namespace FunctionApp1
{
    public class WhatIsMyIp
    {
        [FunctionName("WhatIsMyIP")]
        public async Task Run([TimerTrigger("*/10 * * * * *")] TimerInfo myTimer, ILogger log)
        {
            Output.Log(log,$"C# Timer triggered function \"WhatIsMyIP\" STARTED at: {DateTime.Now}");

            Output.Log(log,"Querying the Public IP");

            Output.Log(log,"   Using HttpClient");

            HttpClient httpClient = new()
            {
                BaseAddress = new Uri("http://icanhazip.com/"),
            };

            using var response = await httpClient.GetAsync("/");

            response.EnsureSuccessStatusCode();
            //.WriteRequestToConsole();
            var body = await response.Content.ReadAsStringAsync();

            Output.Log(log, $"The Public IP seen is: {body}");


            //Output.Log(log,"   Using WebClient");
            //var client = new WebClient();
            //var content = client.DownloadString("http://icanhazip.com/");

            //Output.Log(log,$"The Public IP of this function app is: {content}");

            Output.Log(log,$"C# Timer triggered function \"WhatIsMyIP\" FINISHED at: {DateTime.Now}");
        }
    }

    static class HttpResponseMessageExtensions
    {
        internal static void WriteRequestToConsole(HttpResponseMessage response, ILogger log)
        {
            if (response is null)
            {
                return;
            }

            var request = response.RequestMessage;
            Output.Log(log,$"{request?.Method} " + $"{request?.RequestUri} " + $"HTTP/{request?.Version}" + "\n");
            //            Console.Write($"{request?.Method} ");
            //            Console.Write($"{request?.RequestUri} ");
            //            Console.WriteLine($"HTTP/{request?.Version}");
        }
    }
}
