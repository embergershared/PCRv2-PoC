using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Configuration;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Storage.Blobs;
using WebApp1.Models;
using Azure.Storage.Blobs.Models;

namespace WebApp1.Pages
{
    public class DropCModel : PageModel
    {
        private readonly ILogger<DropCModel> _logger;
        private readonly IConfiguration _configuration;

        public DropCModel(
            ILogger<DropCModel> logger,
            IConfiguration configuration
            )
        {
            _logger = logger;
            _configuration = configuration;
        }

        public async Task OnGetAsync()
        {
            _logger.LogInformation("DropCModel.cshtml.cs: OnGetAsync() invoked");

            var stAcctName = _configuration.GetValue<string>("DropStorageAccountName") ??
                             throw new InvalidOperationException(
                                 "Environment Variable 'DropStorageAccountName' not found.");

            var blobServiceClient = new BlobServiceClient(
                new Uri($"https://{stAcctName}.blob.core.windows.net"),
                new DefaultAzureCredential());

            // Creating a container
            var containerName = "pcr2-poc-" + Guid.NewGuid().ToString();

            // Create the container and return a container client object
            _ = await blobServiceClient.CreateBlobContainerAsync(containerName);

            ViewData["actionDisplay"] = $"Created container {containerName} in Storage account {stAcctName}";

            _logger.LogInformation("DropCModel.cshtml.cs: OnGetAsync() finished");
        }
    }
}
