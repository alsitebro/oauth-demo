using AuthorisationServer.Data;
using Avo.AspNet.Identity.MongoDB;
using log4net;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using log4net.Config;
using MongoDB.Bson;
using MongoDB.Driver;
using SimpleInjector;
using SimpleInjector.Integration.Web;
using SimpleInjector.Integration.Web.Mvc;
using System;
using System.Configuration;
using System.Reflection;
using System.Web.Mvc;

namespace AuthorisationServer
{
    public class IocHandler
    {
        public static Lazy<Container> ContainerInitializer = new Lazy<Container>(() =>
        {
            var mongoClient = new MongoClient(ConfigurationManager.ConnectionStrings["MongoDBConnection"].ConnectionString);
            var container = new Container();
            container.Options.DefaultScopedLifestyle = new WebRequestLifestyle();
            container.Register(() => 
                    mongoClient
                    .GetDatabase("tokenservicedb")
                    .GetCollection<IdentityUser>("oauth2.users"), Lifestyle.Scoped);
            container.Register(() =>
                    mongoClient
                    .GetDatabase("tokenservicedb")
                    .GetCollection<Client>("oauth2.clients"), Lifestyle.Scoped);
            container.Register(() =>
                    mongoClient
                    .GetDatabase("tokenservicedb")
                    .GetCollection<BsonDocument>("oauth2.authorisedclients"), Lifestyle.Scoped);
            container.Register(() =>
                    mongoClient
                    .GetDatabase("tokenservicedb")
                    .GetCollection<Data.Scope>("oauth2.scopes"), Lifestyle.Scoped);
            container.Register(() =>
                    mongoClient
                    .GetDatabase("tokenservicedb")
                    .GetCollection<TokenDocument>("oauth2.tokens"), Lifestyle.Scoped);

            BasicConfigurator.Configure(new log4net.Appender.FileAppender());
            container.Register<ICryptographer, Cryptographer>(Lifestyle.Scoped);
            container.Register(() => LogManager.GetLogger("AuthorisationServer"), Lifestyle.Scoped);
            container.Register<IDataContext<Data.Scope>, MongoDataContext<Data.Scope>>(Lifestyle.Scoped);
            container.Register<IDataContext<Client>, MongoDataContext<Client>>(Lifestyle.Scoped);
            container.Register<IDataContext<TokenDocument>, MongoDataContext<TokenDocument>>(Lifestyle.Scoped);
            container.Register<ClientManager>(Lifestyle.Scoped);
            container.Register<IUserStore<IdentityUser>, IdentityStore<IdentityUser>>(Lifestyle.Scoped);
            container.Register<UserManager<IdentityUser>, UserManager>(Lifestyle.Scoped);
            container.RegisterMvcControllers(Assembly.GetExecutingAssembly());
            DependencyResolver.SetResolver(new SimpleInjectorDependencyResolver(container));
            return container;
        });
    }
}