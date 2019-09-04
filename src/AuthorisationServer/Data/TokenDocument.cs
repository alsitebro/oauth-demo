using System;

namespace AuthorisationServer.Data
{
    public class TokenDocument : BaseEntity
    {
        public string Token { get; set; }
        public string Ticket { get; set; }
        public DateTime Timestamp { get; set; }
    }
}