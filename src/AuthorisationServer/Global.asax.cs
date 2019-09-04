using AuthorisationServer.Data;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Bson.Serialization.IdGenerators;
using System.Web.Mvc;
using System.Web.Routing;

namespace AuthorisationServer
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            RegisterBsonClassMaps();
            IocHandler.ContainerInitializer.Value.Verify();
            MvcHandler.DisableMvcResponseHeader = true;
            AreaRegistration.RegisterAllAreas();
            GlobalFilters.Filters.Add(new HandleErrorAttribute());
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }

        private static void RegisterBsonClassMaps()
        {
            var pack = new ConventionPack { new CamelCaseElementNameConvention() };
            ConventionRegistry.Register("My CamelCase Convention", pack, f => f.FullName.StartsWith("AuthorisationServer."));
            BsonClassMap.RegisterClassMap<BaseEntity>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(i => i.Id).SetIdGenerator(StringObjectIdGenerator.Instance);
            });
        }

        protected void Application_PreSendRequestHeaders()
        {
            Response.Headers.Remove("Server");
        }
    }
}
