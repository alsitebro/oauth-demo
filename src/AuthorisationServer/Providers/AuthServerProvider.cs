using AuthorisationServer.Constants;
using AuthorisationServer.Data;
using Avo.AspNet.Identity.MongoDB;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using MongoDB.Bson;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace AuthorisationServer.Providers
{
    public class AuthServerProvider : OAuthAuthorizationServerProvider
    {
        private readonly ClientManager _clientManager;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthServerProvider(ClientManager clientManager, UserManager<IdentityUser> userManager)
        {
            _clientManager = clientManager;
            _userManager = userManager;
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            var client = _clientManager.Clients.FirstOrDefault(c => c.Id.Equals(context.ClientId)
                                    && c.RedirectUrl.Equals(context.RedirectUri));
            if (client != null)
            {
                context.Validated(context.RedirectUri);
            }
            return Task.CompletedTask;
        }

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            if (context.TryGetBasicCredentials(out var clientId, out var clientSecret) ||
                context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                var client = await _clientManager.FindClientByIdAndSecretAsync(clientId, clientSecret);
                
                if (client == null)
                {
                    context.SetError("invalid_client");
                    return;
                }

                context.Validated(clientId);
            }
        }

        public override Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            if (!ObjectId.TryParse(context.AuthorizeRequest.ClientId, out var mongoObjectId))
            {
                context.SetError("invalid_request");
                return Task.CompletedTask;
            }
            var client =
                _clientManager.Clients.FirstOrDefault(
                    c => c.Id.Equals(context.AuthorizeRequest.ClientId) &&
                         c.RedirectUrl.Equals(context.AuthorizeRequest.RedirectUri));
            if (client == null)
            {
                context.SetError("invalid_client");
            }
            else
            {
                context.Validated();
            }
            return Task.CompletedTask;
        }

        public override async Task ValidateTokenRequest(OAuthValidateTokenRequestContext context)
        {
            if (!ObjectId.TryParse(context.ClientContext.ClientId, out var mongoObjectId))
            {
                context.SetError("invalid_request");
                return;
            }
            var client = await _clientManager.FindClientByIdAsync(context.ClientContext.ClientId);
            if (client == null)
            {
                context.SetError("invalid_client");
            }
            else { context.Validated(); }
        }

        public override async Task GrantAuthorizationCode(OAuthGrantAuthorizationCodeContext context)
        {
            if (context.Ticket.Identity.IsAuthenticated)
            {
                var identity = new ClaimsIdentity(context.Ticket.Identity.Claims, "Bearer");
                var client = await _clientManager.FindClientByIdAsync(context.Ticket.Properties.Dictionary["client_id"]);
                foreach (var scope in client.Scopes)
                {
                    identity.AddClaim(new Claim(CustomClaimTypes.AuthorisedScopes, scope));
                }
                context.Validated(context.Ticket);
            }
            else
            {
                context.OwinContext.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);
            }
            context.Validated(context.Ticket);
        }

        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            if (!ObjectId.TryParse(context.ClientId, out var mongoObjectId))
            {
                context.SetError("invalid_request");
                return;
            }
            var client = await _clientManager.FindClientByIdAsync(context.ClientId);
            if (client == null || !client.IsActive)
            {
                context.SetError("invalid_client");
                return;
            }
            var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType, client.Name, "client_application");
            oAuthIdentity.AddClaim(new Claim("client_id", context.ClientId));
            foreach (var scope in client.Scopes)
            {
                oAuthIdentity.AddClaim(new Claim(CustomClaimTypes.AuthorisedScopes, scope));
            }
            var ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());
            ticket.Properties.Dictionary.Add("client_id", client.Id);
            context.Validated(ticket);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var user = await _userManager.FindAsync(context.UserName, context.Password);
            if (user == null)
            {
                context.SetError("invalid_request", "Authentication failed. Invalid credentials.");
            }

            var signInManager = new SignInManager<IdentityUser, string>(_userManager, context.OwinContext.Authentication);
            var signinStatus = await signInManager.PasswordSignInAsync(context.UserName, context.Password, false, true);

            switch (signinStatus)
            {
                case SignInStatus.LockedOut:
                    if (_userManager.CheckPassword(user, context.Password))
                    {
                        context.SetError("invalid_request", "Your account has been locked out");
                    }
                    else
                    {
                        context.SetError("invalid_request", "Sign in failed");
                    }
                    break;
                case SignInStatus.Success:
                    var identity = await _userManager.CreateIdentityAsync(user, OAuthDefaults.AuthenticationType);
                    context.Validated(new AuthenticationTicket(identity, new AuthenticationProperties()));
                    break;
                default:
                    context.SetError("invalid_request", "Sign in failed");
                    break;
            }
        }

        public override async Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            if (!ObjectId.TryParse(context.ClientId, out var mongoObjectId))
            {
                context.SetError("invalid_request");
                return;
            }
            var client = await _clientManager.FindClientByIdAsync(context.ClientId);
            if (client == null || !client.IsActive)
            {
                context.SetError("invalid_client");
                return;
            }
            var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType, client.Name, "client_application");
            oAuthIdentity.AddClaim(new Claim("client_id", context.ClientId));
            foreach (var scope in client.Scopes)
            {
                oAuthIdentity.AddClaim(new Claim(CustomClaimTypes.AuthorisedScopes, scope));
            }
            var ticket = new AuthenticationTicket(oAuthIdentity, new AuthenticationProperties());
            ticket.Properties.Dictionary.Add("client_id", client.Id);
            context.Validated(ticket);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            return base.TokenEndpoint(context);
        }

        public override async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        {
            if (context.AuthorizeRequest.IsAuthorizationCodeGrantType)
            {
                if (!HttpContext.Current.Request.IsAuthenticated)
                {
                    context.OwinContext.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);
                }
                else
                {
                    var redirectUri = context.AuthorizeRequest.RedirectUri;
                    var clientId = context.AuthorizeRequest.ClientId;
                    var state = context.AuthorizeRequest.State;
                    var sb = new StringBuilder();
                    foreach (var scope in context.AuthorizeRequest.Scope)
                    {
                        sb.Append($"{scope},");
                    }
                    var scopes = sb.ToString().Trim(',');
                    var identity = context.Request.User.Identity as ClaimsIdentity;
                    var client = await _clientManager.FindClientByIdAsync(clientId).ConfigureAwait(false);
                    var authorisationCodeContext = new AuthenticationTokenCreateContext(context.OwinContext, context.Options.AuthorizationCodeFormat,
                        new AuthenticationTicket(identity,
                        new AuthenticationProperties(new Dictionary<string, string>
                        {
                            { "client_id", clientId},
                            { "redirect_uri", redirectUri},
                            { "response_type", context.AuthorizeRequest.ResponseType },
                            { "state", state },
                            { "user_id", identity.GetUserId() },
                            { "scopes",  scopes }
                        })
                        {
                            IssuedUtc = DateTimeOffset.Now,
                            ExpiresUtc = DateTimeOffset.Now.Add(context.Options.AuthorizationCodeExpireTimeSpan)
                        }));
                    await context.Options.AuthorizationCodeProvider.CreateAsync(authorisationCodeContext);
                    AuthenticateClient(context.OwinContext, identity, client);
                }
            }
        }

        public override Task AuthorizationEndpointResponse(OAuthAuthorizationEndpointResponseContext context)
        {
            var redirectUri = context.AuthorizeEndpointRequest.RedirectUri;
            if (context.AuthorizeEndpointRequest.IsAuthorizationCodeGrantType)
            {
                redirectUri = $"{redirectUri}?code={context.AuthorizationCode}&redirect_uri={context.AuthorizeEndpointRequest.RedirectUri}";
                if (!string.IsNullOrEmpty(context.AuthorizeEndpointRequest.State))
                {
                    redirectUri = $"{redirectUri}&state={context.AuthorizeEndpointRequest.State}";
                }
            }
            if (context.AuthorizeEndpointRequest.IsImplicitGrantType)
            {
                redirectUri = $"{redirectUri}?access_token={context.AccessToken}";
                if (!string.IsNullOrEmpty(context.AuthorizeEndpointRequest.State))
                {
                    redirectUri += $"&state={context.AuthorizeEndpointRequest.State}";
                }
                redirectUri += $"&token_type=bearer&expires_in={context.Properties.ExpiresUtc}";
            }
            context.Response.Redirect(redirectUri);
            context.RequestCompleted();
            return Task.CompletedTask;
            //return base.AuthorizationEndpointResponse(context);
        }

        public override Task TokenEndpointResponse(OAuthTokenEndpointResponseContext context)
        {
            return base.TokenEndpointResponse(context);
        }

        public override Task GrantCustomExtension(OAuthGrantCustomExtensionContext context)
        {
            return base.GrantCustomExtension(context);
        }

        public override Task MatchEndpoint(OAuthMatchEndpointContext context)
        {
            return base.MatchEndpoint(context);
        }

        private void AuthenticateClient(IOwinContext owinContext, ClaimsIdentity user, Client client)
        {
            var identity = new ClaimsIdentity(user?.Claims, "Bearer", user?.NameClaimType, user?.RoleClaimType);
            foreach (var scope in client.Scopes)
            {
                identity.AddClaim(new Claim(CustomClaimTypes.AuthorisedScopes, scope));
            }
            owinContext.Authentication.SignIn(identity);
        }
    }
}