using System.ComponentModel.DataAnnotations;

namespace AuthorisationServer.Models
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}