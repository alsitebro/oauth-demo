using System.Collections.Generic;

namespace AuthorisationServer.Data
{
    public class Client : BaseEntity
    {
        public string RedirectUrl { get; set; }
        public string Name { get; set; }
        public IEnumerable<string> Scopes { get; set; }
        public bool IsActive { get; set; }
        public string Secret { get; set; }
    }
}