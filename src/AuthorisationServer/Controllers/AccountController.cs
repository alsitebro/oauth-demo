using AuthorisationServer.Data;
using AuthorisationServer.Models;
using Avo.AspNet.Identity.MongoDB;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace AuthorisationServer.Controllers
{
    public class AccountController : Controller
    {
        public UserManager<IdentityUser> UserManager { get; }
        public IAuthenticationManager AuthenticationManager => HttpContext.GetOwinContext().Authentication;
        public SignInManager<IdentityUser, string> SignInManager => 
            new SignInManager<IdentityUser, string>(UserManager, AuthenticationManager);

        public AccountController(UserManager<IdentityUser> userManager)
        {
            UserManager = userManager;
        }

        public ActionResult Login()
        {
            return View(new LoginViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var signinStatus = await SignInManager.PasswordSignInAsync(model.Email, model.Password, false, true).ConfigureAwait(false);
            var user = UserManager.FindByName(model.Email);

            switch (signinStatus)
            {
                case SignInStatus.LockedOut:
                    ModelState.AddModelError("", user != null
                        && UserManager.CheckPassword(user, model.Password)
                        ? "Your account has been locked out"
                        : "Sign in failed");
                    return View();
                case SignInStatus.Success:
                    var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie).ConfigureAwait(false);
                    identity.AddClaim(new Claim("user_id", user.Id));
                    AuthenticationManager.SignIn(identity);
                    return Redirect(Request.QueryString["ReturnUrl"] ?? "/");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Sign in failed");
                    return View();
            }
        }

        public ActionResult Logout()
        {
            AuthenticationManager.SignOut("ApplicationCookie");
            AuthenticationManager.SignOut("Bearer");
            return Redirect(Request.QueryString["ReturnUrl"] ?? "/");
        }

        public ActionResult Register()
        {
            return View(new RegisterViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            if (!model.Password.Equals(model.ConfirmPassword))
            {
                ModelState.AddModelError("Confirm", "Passwords must match");
                return View(model);
            }
            var checkForDuplicate = await UserManager.FindByNameAsync(model.Email).ConfigureAwait(false);
            if (checkForDuplicate == null)
            {
                var user = new IdentityUser(model.Email);
                var result = await UserManager.CreateAsync(user, model.Password).ConfigureAwait(false);
                if (result.Errors.Any())
                {
                    ModelState.AddModelError("", "Registration failed. Please try again later. If this is not the first time you're getting this message, contact Customer Services immediately.");
                    return View(model);
                }
                await UserManager.AddClaimAsync(user.Id, new Claim(ClaimTypes.Role, "User")).ConfigureAwait(false);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}