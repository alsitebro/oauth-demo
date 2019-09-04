using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthorisationServer.Data
{
    public class ClientManager
    {
        private readonly IDataContext<Client> _clientContext;

        public ClientManager(IDataContext<Client> clientContext)
        {
            _clientContext = clientContext;
        }

        public List<Client> Clients => _clientContext.ToList();

        public async Task<Client> FindClientByIdAsync(string clientId)
        {
            return await _clientContext.SingleOrDefaultAsync(c => c.Id.Equals(clientId));
        }

        public async Task<Client> FindClientByIdAndSecretAsync(string clientId, string clientSecret)
        {
            return await _clientContext.SingleOrDefaultAsync(c => c.Id.Equals(clientId) && c.Secret.Equals(clientSecret));
        }

        public async Task RegisterClientAsync(Client client)
        {
            if (await _clientContext.SingleOrDefaultAsync(c => c.Name.Equals(client.Name)) == null)
            {
                await _clientContext.CreateOneAsync(client);
            }
        }

        public async Task DeleteClientAsync(string clientId)
        {
            await _clientContext.DeleteOneAsync(clientId);
        }
    }
}