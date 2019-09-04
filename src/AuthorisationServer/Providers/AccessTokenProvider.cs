using AuthorisationServer.Data;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorisationServer.Providers
{
    public class AccessTokenProvider : AuthenticationTokenProvider
    {
        private readonly IDataContext<TokenDocument> tokenDataContext;
        private readonly ICryptographer cryptographer;

        public AccessTokenProvider(IDataContext<TokenDocument> tokenDataContext, ICryptographer cryptographer)
        {
            this.tokenDataContext = tokenDataContext;
            this.cryptographer = cryptographer;
            OnReceive = ReceiveAuthenticationCode;
            OnCreate = CreateAuthenticationCode;
            OnReceiveAsync = ReceiveAuthenticationCodeAsync;
            OnCreateAsync = CreateAuthenticationCodeAsync;
        }
        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            Task.Run(async () => await ReceiveAuthenticationCodeAsync(context));
        }

        private async Task CreateAuthenticationCodeAsync(AuthenticationTokenCreateContext context)
        {
            context.SetToken($"{Guid.NewGuid().ToString("n")}{Guid.NewGuid().ToString("n")}");

            await tokenDataContext.CreateOneAsync(new TokenDocument
            {
                Token = context.Token,
                Ticket = context.SerializeTicket(),
                Timestamp = DateTime.Now,
            });
        }

        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            Task.Run(async () => await CreateAuthenticationCodeAsync(context));
        }

        private async Task ReceiveAuthenticationCodeAsync(AuthenticationTokenReceiveContext context)
        {
            var token = await tokenDataContext.SingleOrDefaultAsync(t => t.Token.Equals(context.Token));
            if (token != null)
            {
                context.DeserializeTicket(token.Ticket);
            }
        }
    }
}