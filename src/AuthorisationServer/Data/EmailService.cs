using Microsoft.AspNet.Identity;
using System;
using System.Configuration;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace AuthorisationServer.Data
{
    public class EmailService : IIdentityMessageService
    {
        public async Task SendAsync(IdentityMessage message)
        {
            using (var mail = new MailMessage(ConfigurationManager.AppSettings["MailFrom"], message.Destination))
            {
                mail.Subject = "OAuth User Registration";
                mail.Body = message.Body;
                mail.IsBodyHtml = true;
                mail.BodyEncoding = Encoding.UTF8;
                await new SmtpClient(ConfigurationManager.AppSettings["SMTPHost"])
                {
                    Port = Convert.ToInt32(ConfigurationManager.AppSettings["SMTPPort"])
                }
                .SendMailAsync(mail);
            }
        }
    }
}