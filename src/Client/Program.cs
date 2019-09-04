using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;

namespace Client
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .ConfigureKestrel(kestrelOptions =>
                {
                    kestrelOptions.Limits.MaxRequestBodySize = 65536;
                    kestrelOptions.Limits.MaxRequestHeadersTotalSize = 65536;
                })
                .UseStartup<Startup>();
    }
}
