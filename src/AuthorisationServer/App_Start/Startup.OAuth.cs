using AuthorisationServer.Constants;
using AuthorisationServer.Data;
using AuthorisationServer.Providers;
using Avo.AspNet.Identity.MongoDB;
using log4net;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;

namespace AuthorisationServer
{
    public partial class Startup
    {
        public void OAuthConfiguration(IAppBuilder appBuilder)
        {
            var container = IocHandler.ContainerInitializer.Value;
            var clientManager = container.GetInstance<ClientManager>();
            var userManager = container.GetInstance<UserManager<IdentityUser>>();
            var tokenDataContext = container.GetInstance<IDataContext<TokenDocument>>();
            var authServerProvider = new AuthServerProvider(clientManager, userManager);
            var oauthServerOptions = new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString(Paths.AuthorisePath),
                TokenEndpointPath = new PathString(Paths.TokenPath),
                ApplicationCanDisplayErrors = true,
                AllowInsecureHttp = false,
                Provider = authServerProvider,
                AuthorizationCodeProvider = new AccessTokenProvider(tokenDataContext, new Cryptographer()),
                AccessTokenProvider = new AccessTokenProvider(tokenDataContext, new Cryptographer()),
                RefreshTokenProvider = new AccessTokenProvider(tokenDataContext, new Cryptographer()),
                AuthorizationCodeFormat = BuildSecureDataFormat(typeof(OAuthAuthorizationServerMiddleware).FullName, "Authorisation_Code", "V1"),
                AccessTokenFormat = BuildSecureDataFormat(typeof(OAuthAuthorizationServerMiddleware).Namespace, "Access_Token", "V1"),
                RefreshTokenFormat = BuildSecureDataFormat(typeof(OAuthAuthorizationServerMiddleware).Namespace, "Refresh_Token", "V1"),
                AuthenticationMode = AuthenticationMode.Active,
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(2),
                AuthorizationCodeExpireTimeSpan = TimeSpan.FromMinutes(10),
            };
            appBuilder.UseOAuthAuthorizationServer(oauthServerOptions);
        }
    }
}