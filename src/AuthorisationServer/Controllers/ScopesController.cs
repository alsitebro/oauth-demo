using AuthorisationServer.Data;
using AuthorisationServer.Models;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace AuthorisationServer.Controllers
{
    [Authorize]
    public class ScopesController : Controller
    {
        private readonly IDataContext<Scope> _scopeContext;

        public ScopesController(IDataContext<Scope> scopeContext)
        {
            _scopeContext = scopeContext;
        }

        public ActionResult Index()
        {
            return View(_scopeContext.ToList());
        }

        public ActionResult Create()
        {
            return View(new NewScopeModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(NewScopeModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            await _scopeContext.CreateOneAsync(new Scope { Name = model.Name, Description = model.Description }).ConfigureAwait(false);
            return RedirectToAction("Index");
        }
    }
}