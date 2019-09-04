using System.Collections.Generic;
using System.ComponentModel;
using System.Web.Mvc;

namespace AuthorisationServer.Models
{
    public class NewClientModel
    {
        public string Name { get; set; }
        [DisplayName("Redirect URL")]
        public string RedirectUrl { get; set; }
        [DisplayName("Scopes")]
        public List<string> SelectedScopes { get; set; }
        public List<SelectListItem> ScopeList { get; set; } = new List<SelectListItem>();
    }
}