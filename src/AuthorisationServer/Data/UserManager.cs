using Avo.AspNet.Identity.MongoDB;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;

namespace AuthorisationServer.Data
{
    public class UserManager : UserManager<IdentityUser>
    {
        public UserManager(IUserStore<IdentityUser> store) : base(store)
        {
            PasswordValidator = new PasswordValidator
            {
                RequireDigit = true,
                RequireLowercase = true,
                RequireNonLetterOrDigit = true,
                RequireUppercase = true,
                RequiredLength = 6
            };
            DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            MaxFailedAccessAttemptsBeforeLockout = 5;
            UserLockoutEnabledByDefault = true;
            UserLockoutEnabledByDefault = true;
            DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            MaxFailedAccessAttemptsBeforeLockout = 5;
            EmailService = new EmailService();
        }

        public static UserManager<IdentityUser> Create(IOwinContext context, 
            IdentityStore<IdentityUser> store, 
            IdentityFactoryOptions<UserManager<IdentityUser>> options)
        {
            var manager = new UserManager(store);
            manager.UserValidator = new UserValidator<IdentityUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<IdentityUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }
}