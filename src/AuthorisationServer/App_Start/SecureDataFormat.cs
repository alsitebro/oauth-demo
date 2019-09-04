using log4net;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;
using System;

namespace AuthorisationServer
{
    public class SecureDataFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly IDataProtector dataProtector;
        private readonly IDataSerializer<AuthenticationTicket> serializer;
        private readonly ITextEncoder encoder;
        private readonly ILog logger;

        public SecureDataFormat(IDataSerializer<AuthenticationTicket> serializer, IDataProtector dataProtector, ITextEncoder encoder, ILog logger)
        {
            this.serializer = serializer;
            this.dataProtector = dataProtector;
            this.encoder = encoder;
            this.logger = logger;
        }
        public string Protect(AuthenticationTicket data)
        {
            var serialisedData = serializer.Serialize(data);
            var protectedData = dataProtector.Protect(serialisedData);
            var protectedText = encoder.Encode(protectedData);
            return protectedText;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            AuthenticationTicket ticket = null;
            try
            {
                var protectedData = encoder.Decode(protectedText);
                var serializedData = dataProtector.Unprotect(protectedData);
                ticket = serializer.Deserialize(serializedData);
            }
            catch (Exception ex)
            {
                logger.Error($"{DateTime.Now} {ex.Message}");
                if(ex.InnerException?.Message != null)
                {
                    logger.Error($"{DateTime.Now} {ex.InnerException.Message}");
                }
            }
            return ticket;
        }
    }
}