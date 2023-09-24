using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace WebApp1.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        internal string LocalIp { get; private set; }
        internal string RemoteIp { get; private set; }
        internal string Scheme { get; private set; }
        internal string Host { get; private set; }
        internal string HostHeader { get; private set; }
        internal string XForwardedFor { get; private set; }
        internal string XComingFrom { get; private set; }


        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("IndexModel.cshtml.cs: OnGet() invoked");

            // Gathering request infos:
            LocalIp = HttpContext.Connection.LocalIpAddress?.ToString();
            RemoteIp =
                $"{HttpContext.Connection.RemoteIpAddress}:{HttpContext.Connection.RemotePort}";
            HostHeader = HttpContext.Request.Headers.Host.ToString();

            Scheme = HttpContext.Request.Scheme;
            Host = HttpContext.Request.Host.ToString();

            XForwardedFor = Request.Headers["X-Forwarded-For"].ToString();
            //XComingFrom = Request.Headers["X-Coming-From"].ToString();

            _logger.LogInformation("IndexModel.cshtml.cs: OnGet() finished");
        }
    }
}