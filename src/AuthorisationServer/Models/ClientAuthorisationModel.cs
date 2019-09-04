using System.Collections.Generic;

namespace AuthorisationServer.Models
{
    public class ClientAuthorisationModel
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string RedirectUrl { get; set; }
        public List<string> Scopes { get; set; } = new List<string>();
    }
}