using Microsoft.Owin.Security.DataProtection;
using System;
using System.Web.Security;

namespace AuthorisationServer
{
    public class MachineKeyDataProtector : IDataProtector
    {
        private readonly string[] _purposes;

        private MachineKeyDataProtector(params string[] purposes)
        {
            _purposes = purposes;
        }

        public static MachineKeyDataProtector Create(params string[] purposes)
        {
            return new MachineKeyDataProtector(purposes);
        }

        public byte[] Protect(byte[] userData)
        {
            if (userData.Length == 0)
            {
                throw new InvalidOperationException("Invalid request");
            }
            return MachineKey.Protect(userData, _purposes);
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            if (protectedData.Length == 0)
            {
                throw new InvalidOperationException("Invalid request");
            }
            return MachineKey.Unprotect(protectedData, _purposes);
        }
    }
}