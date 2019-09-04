using AuthorisationServer.Constants;
using Avo.AspNet.Identity.MongoDB;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;
using Owin;
using System;

namespace AuthorisationServer
{
    public partial class Startup
    {
        public void IdentityConfiguration(IAppBuilder appBuilder)
        {
            var container = IocHandler.ContainerInitializer.Value;
            appBuilder.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                AuthenticationMode = AuthenticationMode.Active,
                LoginPath = new PathString(Paths.LoginPath),
                LogoutPath = new PathString(Paths.LogoutPath),
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity =
                      SecurityStampValidator.OnValidateIdentity<UserManager<IdentityUser>, IdentityUser>(
                          TimeSpan.FromMinutes(20),
                          (manager, user) =>
                          {
                              var userIdentity =
                                  manager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
                              return userIdentity;
                          })
                },
                ExpireTimeSpan = TimeSpan.FromMinutes(20),
                CookieSecure = CookieSecureOption.Always,
                TicketDataFormat = BuildSecureDataFormat(typeof(CookieAuthenticationMiddleware).Namespace, "ApplicationCookie", "V1"),
                SlidingExpiration = true,
            });
            appBuilder.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationTypes.ApplicationCookie);
        }
    }
}