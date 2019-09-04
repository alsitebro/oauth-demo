using AuthorisationServer.Data;
using Avo.AspNet.Identity.MongoDB;
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace AuthorisationServer.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
    }
}