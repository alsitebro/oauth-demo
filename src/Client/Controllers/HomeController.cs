using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Client.Models;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace Client.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            var model = new HomeModel();
            foreach (var claim in HttpContext.User.Claims)
            {
                model.Claims.Add(claim.Type, claim.Value);
            }
            return View(model);
        }

        public IActionResult OAuthSignin()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            var principal = User.Identity as ClaimsIdentity;
            return View();
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync("Cookies");
            return Redirect($"https://localhost:44308/Account/Logout?ReturnUrl=https://localhost:5001");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
