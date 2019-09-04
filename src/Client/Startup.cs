using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Client
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => false;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });
            
            services.AddAuthentication(opt =>
            {
                opt.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme = "Bearer";
                opt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOAuth("Bearer", options =>
            {
                options.AuthorizationEndpoint = "https://localhost:44308/OAuth/Authorize";
                options.TokenEndpoint = "https://localhost:44308/Token";
                options.CallbackPath = new PathString("/acme-signin");
                options.ClientId = "5d5336d88a5b064620fcedf5";
                options.ClientSecret = "AAzy5Evs1REACypB40dRGFAZgDZmQcpko+y7JZzjYCRBYlCW+9ni012lC07KmO0yPg==";
                options.Scope.Add("user-read");
                options.ClaimActions.MapJsonKey("urn:oauth:scope", "scope", "string");
                options.SaveTokens = true;
                options.Events.OnCreatingTicket = ctx =>
                {
                    List<AuthenticationToken> tokens = ctx.Properties.GetTokens().ToList();
                    tokens.Add(new AuthenticationToken()
                    {
                        Name = "TicketCreated",
                        Value = DateTime.UtcNow.ToString()
                    });
                    
                    ctx.Properties.StoreTokens(tokens);
                    ctx.RunClaimActions();
                    return Task.CompletedTask;
                };

                options.Events.OnTicketReceived = ctx =>
                {
                    var tokens = ctx.Properties.GetTokens().ToList();
                    tokens.Add(new AuthenticationToken()
                    {
                        Name = "TicketReceived",
                        Value = DateTime.UtcNow.ToString()
                    });
                    ctx.Properties.StoreTokens(tokens);
                    return Task.CompletedTask;
                };

                options.Events.OnRemoteFailure = ctx => 
                {
                    var test = ctx;
                    return Task.CompletedTask;
                };
            });
            services.AddMvc()
                .SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "oauthSignin",
                    template: "acme-signin",
                    defaults: new { controller = "Home", Action = "OAuthSignin" });
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
