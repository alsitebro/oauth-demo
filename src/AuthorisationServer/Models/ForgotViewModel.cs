using System.ComponentModel.DataAnnotations;

namespace AuthorisationServer.Models
{
    public class ForgotViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}