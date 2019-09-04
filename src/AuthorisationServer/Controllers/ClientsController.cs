using AuthorisationServer.Data;
using AuthorisationServer.Models;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace AuthorisationServer.Controllers
{
    public class ClientsController : Controller
    {
        private readonly ClientManager _clientManager;
        private readonly IDataContext<Scope> _scopeContext;


        public ClientsController(ClientManager clientManager, IDataContext<Scope> scopeContext)
        {
            _clientManager = clientManager;
            _scopeContext = scopeContext;
        }

        public ActionResult Index()
        {
            return View(_clientManager.Clients);
        }

        public ActionResult Register()
        {
            var scopeList = _scopeContext.ToList()
                .Select(s => new SelectListItem { Text = s.Description, Value = s.Name })
                .ToList();

            return View(new NewClientModel { ScopeList = scopeList });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(NewClientModel model)
        {
            model.ScopeList = _scopeContext.ToList()
                .Select(s => new SelectListItem { Text = s.Description, Value = s.Name })
                .ToList();

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            await _clientManager.RegisterClientAsync(new Client
            {
                Name = model.Name,
                RedirectUrl = model.RedirectUrl,
                Secret = GenerateSecret(),
                Scopes = model.SelectedScopes
            }).ConfigureAwait(false);

            return RedirectToAction("Index");
        }

        private string GenerateSecret()
        {
            return new PasswordHasher().HashPassword(Guid.NewGuid().ToString("N") + DateTime.Now.ToString("O"));
        }

        public async Task<ActionResult> Details(string id)
        {
            var model = await _clientManager.FindClientByIdAsync(id);
            if (model == null)
            {
                return RedirectToAction("Index");
            }
            return View(model);
        }

        public async Task<ActionResult> Delete(string id)
        {
            var model = await _clientManager.FindClientByIdAsync(id);
            if (model == null)
            {
                return RedirectToAction("Index");
            }
            return View(model);
        }

        [HttpPost]
        [ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ConfirmDelete(string id)
        {
            await _clientManager.DeleteClientAsync(id).ConfigureAwait(false);
            return RedirectToAction("Index");
        }
    }
}