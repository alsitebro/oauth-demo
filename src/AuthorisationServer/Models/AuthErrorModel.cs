using Microsoft.Owin;

namespace AuthorisationServer.Models
{
    public class AuthErrorModel
    {
        public AuthErrorModel(string error, string description, string errorUri = "")
        {
            Error = error;
            Description = description;
            ErrorUri = errorUri;
        }
        public AuthErrorModel(IOwinContext owinContext)
        {
            Error = owinContext.Get<string>("oauth.Error");
            Description = owinContext.Get<string>("oauth.ErrorDescription");
            ErrorUri = owinContext.Get<string>("oauth.ErrorUri");
        }

        public string Error { get; }
        public string Description { get; }
        public string ErrorUri { get; }
    }
}