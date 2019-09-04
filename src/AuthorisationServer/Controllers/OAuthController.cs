using AuthorisationServer.Constants;
using AuthorisationServer.Data;
using AuthorisationServer.Models;
using Avo.AspNet.Identity.MongoDB;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace AuthorisationServer.Controllers
{
    [Authorize]
    public class OAuthController : Controller
    {
        private readonly ClientManager _clientManager;
        private IDataContext<Scope> _scopeContext;
        public UserManager<IdentityUser> UserManager { get; }
        public IAuthenticationManager AuthenticationManager => Request.GetOwinContext().Authentication;

        public OAuthController(UserManager<IdentityUser> userManager, ClientManager clientManager, IDataContext<Scope> scopeContext)
        {
            _clientManager = clientManager;
            _scopeContext = scopeContext;
            UserManager = userManager;
        }

        public ActionResult Authorize()
        {
            var clientId = Server.UrlDecode(Request.QueryString.Get("client_id"));
            var redirectUri = Server.UrlDecode(Request.QueryString.Get("redirect_uri"));
            var client = _clientManager.Clients.SingleOrDefault(c => c.Id == clientId && c.RedirectUrl == redirectUri);
            if (client == null)
            {
                var errorModel = new AuthErrorModel("Invalid request", "Invalid request. Unknown client");
                return View("AuthorizeError", errorModel);
            }
            var user = User.Identity as ClaimsIdentity;
            if (user.HasClaim(c => c.Type.Equals(CustomClaimTypes.AuthorisedClient) && c.Value.Equals(client.Id)))
            {
                ViewBag.UserAlreadyAuthorisedClient = true;
            }
            var viewModel = new ClientAuthorisationModel
            {
                Id = client.Id,
                Name = client.Name,
                RedirectUrl = client.RedirectUrl
            };
            viewModel.Scopes.AddRange(_scopeContext.ToList()
                    .Where(s => client.Scopes.Contains(s.Name)).Select(i => i.Description));
            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Authorize(ClientAuthorisationModel model)
        {
            if (!string.IsNullOrEmpty(Request.Form.Get("Grant")))
            {
                var client =
                await _clientManager.FindClientByIdAsync(model.Id).ConfigureAwait(false);
                if (client == null)
                {
                    var errorModel = new AuthErrorModel("Invalid request", "Unknown client");
                    return View("AuthorizeError", errorModel);
                }
                var user = User.Identity as ClaimsIdentity;
                if (!user.HasClaim(CustomClaimTypes.AuthorisedClient, client.Id))
                {
                    var result = await UserManager.AddClaimAsync(user.GetUserId(), new Claim(CustomClaimTypes.AuthorisedClient, client.Id)).ConfigureAwait(false);
                }
            }
            else if (!string.IsNullOrEmpty(Request.Form.Get("Logout")))
            {
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                AuthenticationManager.Challenge(DefaultAuthenticationTypes.ApplicationCookie);
                return new HttpUnauthorizedResult();
            }
            var redirectUri = $"{Paths.AuthorisePath}?{Request.RawUrl.Split('?')[1]}";
            return Redirect(redirectUri);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Token()
        {
            return View();
        }
    }
}