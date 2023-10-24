using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System;

namespace WebApp1.Pages
{
    public class ArchiveCModel : PageModel
    {

        private readonly ILogger<ArchiveCModel> _logger;
        private readonly IConfiguration _configuration;

        public ArchiveCModel(
            ILogger<ArchiveCModel> logger,
            IConfiguration configuration
        )
        {
            _logger = logger;
            _configuration = configuration;
        }

        public async Task OnGetAsync()
        {
            _logger.LogInformation("ArchiveCModel.cshtml.cs: OnGetAsync() invoked");
            var stAcctName = _configuration.GetValue<string>("ArchiveStorageAccountName") ??
                             throw new InvalidOperationException(
                                 "Environment Variable 'ArchiveStorageAccountName' not found.");

            var blobServiceClient = new BlobServiceClient(
                new Uri($"https://{stAcctName}.blob.core.windows.net"),
                new DefaultAzureCredential());

            // Creating a container
            var containerName = "pcr2-poc-" + Guid.NewGuid().ToString();

            // Create the container and return a container client object
            try
            {
                _ = await blobServiceClient.CreateBlobContainerAsync(containerName);
            }
            catch (Exception ex)
            {
                _logger.LogError($"CreateBlobContainerAsync() threw an exception: {ex}");
            }

            ViewData["actionDisplay"] = $"Created container {containerName} in Storage account {stAcctName}";

            _logger.LogInformation("ArchiveCModel.cshtml.cs: OnGetAsync() finished");
        }
    }
}
