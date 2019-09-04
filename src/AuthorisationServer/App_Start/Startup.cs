using log4net;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Owin;
using System.Configuration;
using System.Threading.Tasks;
using System.Web.Cors;

namespace AuthorisationServer
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder appBuilder)
        {
            IdentityConfiguration(appBuilder);
            var corsOptions = new CorsOptions
            {
                PolicyProvider = new CorsPolicyProvider
                {
                    PolicyResolver = req =>
                    {
                        var policy = new CorsPolicy();
                        var corsOrigins = ConfigurationManager.AppSettings["CorsOrigins"].Split(',');
                        var corsMethods = ConfigurationManager.AppSettings["CorsMethod"].Split(',');
                        foreach (var origin in corsOrigins)
                        {
                            if (!string.IsNullOrEmpty(origin))
                            {
                                policy.Origins.Add(origin);
                            }
                        }
                        foreach (var method in corsMethods)
                        {
                            if (!string.IsNullOrEmpty(method))
                            {
                                policy.Methods.Add(method);
                            }
                        }
                        return Task.FromResult(policy);
                    }
                },
                CorsEngine = new CorsEngine()
            };
            appBuilder.UseCors(corsOptions);
            OAuthConfiguration(appBuilder);
        }

        private static SecureDataFormat BuildSecureDataFormat(params string[] purposes) => new SecureDataFormat(new TicketSerializer(),
                                    MachineKeyDataProtector.Create(purposes),
                                    TextEncodings.Base64Url,
                                    LogManager.GetLogger(typeof(ISecureDataFormat<AuthenticationTicket>)));
    }
}