namespace AuthorisationServer.Data
{
    public class Scope : BaseEntity
    {
        public string Name { get; set; }
        public string Description { get; set; }
    }
}