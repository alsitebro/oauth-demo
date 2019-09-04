using System.Web.Mvc;
using System.Web.Routing;

namespace AuthorisationServer
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            routes.MapRoute(
               name: "OAuthAuthorize",
               url: "Authorize",
               defaults: new { controller = "OAuth", action = "Authorize" });

            routes.MapRoute(
                name: "OAuthToken",
                url: "Token",
                defaults: new { controller = "OAuth", action = "Token" });
            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional }
            );
        }
    }
}
