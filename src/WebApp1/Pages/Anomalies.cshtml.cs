using System;
using System.Linq;
using System.Threading.Tasks;
using Azure.AI.AnomalyDetector;
using Azure;
using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Azure.Storage.Blobs.Models;

namespace WebApp1.Pages
{
    public class AnomaliesModel : PageModel
    {
        private readonly ILogger<AnomaliesModel> _logger;
        private readonly IConfiguration _configuration;

        public AnomaliesModel(
            ILogger<AnomaliesModel> logger,
            IConfiguration configuration
        )
        {
            _logger = logger;
            _configuration = configuration;
        }

        public async Task OnGetAsync()
        {
            _logger.LogInformation("AnomaliesModel.cshtml.cs: OnGetAsync() invoked");

            var endpoint = _configuration.GetValue<string>("AnDetEndpoint") ??
                           throw new InvalidOperationException(
                               "Environment Variable 'AnDetEndpoint' not found.");
            var apiKey = _configuration.GetValue<string>("AnDetKey") ??
                         throw new InvalidOperationException(
                             "Environment Variable 'AnDetKey' not found.");

            var stAcctName = _configuration.GetValue<string>("ArchiveStorageAccountName") ??
                             throw new InvalidOperationException(
                                 "Environment Variable 'ArchiveStorageAccountName' not found.");
            var contName = _configuration.GetValue<string>("ArchiveAnDetContainerName") ??
                           throw new InvalidOperationException(
                               "Environment Variable 'ArchiveAnDetContainerName' not found.");
            var blobName = _configuration.GetValue<string>("ArchiveAnDetBlobName") ??
                           throw new InvalidOperationException(
                               "Environment Variable 'ArchiveAnDetBlobName' not found.");

            //create AD client
            var endpointUri = new Uri(endpoint);
            var credential = new AzureKeyCredential(apiKey);
            AnomalyDetectorClient client = new(endpointUri, credential);

            // create Storage account client
            var blobServiceClient = new BlobServiceClient(
                new Uri($"https://{stAcctName}.blob.core.windows.net"),
                new DefaultAzureCredential()
            );

            // Access container
            var blobContainerClient = blobServiceClient.GetBlobContainerClient(contName);
            // Access blob
            var blobClient = blobContainerClient.GetBlobClient(blobName);

            // Download blob
            var content = await DownloadBlobToStringAsync(blobClient);

            // Process data input
            var data = content.Split("\r\n");
            var list2 = data
                .Select(line => new TimeSeriesPoint(float.Parse(line.Split(",")[1])) { Timestamp = DateTime.Parse(line.Split(",")[0]) })
                .ToList();

            //create request
            var request = new UnivariateDetectionOptions(list2)
            {
                Granularity = TimeGranularity.Daily
            };

            UnivariateEntireDetectionResult result = await client.DetectUnivariateEntireSeriesAsync(request);

            var output = string.Empty;
            var hasAnomaly = false;
            for (var i = 0; i < request.Series.Count; ++i)
            {
                if (result.IsAnomaly[i])
                {
                    output += $"Anomaly detected at line: {i + 1}.\r\n";
                    hasAnomaly = true;
                }
            }
            if (!hasAnomaly)
            {
                output = "No anomalies detected in the series.";
            }

            ViewData["result"] = output;

            _logger.LogInformation("AnomaliesModel.cshtml.cs: OnGetAsync() finished");
        }

        public static async Task<string> DownloadBlobToStringAsync(BlobClient blobClient)
        {
            BlobDownloadResult downloadResult = await blobClient.DownloadContentAsync();
            return downloadResult.Content.ToString();
        }

    }
}
