using System.ComponentModel.DataAnnotations;

namespace CookieAuthentication.Models
{
    public class RegisterViewModel
    {
        [Display(Name = "Kullanıcı Adı")]
        [Required(ErrorMessage = "Kullanıcı adı boş bırakılamaz.")]
        [StringLength(30, ErrorMessage = "Kullanıcı adı en fazla 30 karakter içermelidir.")]
        public string Username { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Şifre")]
        [Required(ErrorMessage = "Şifre boş bırakılamaz.")]
        [MinLength(6, ErrorMessage = "Şifre en az 6 karakter içermelidir.")]
        [MaxLength(16, ErrorMessage = "Şifre en fazla 16 karakter içerebilir.")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Şifre Tekrar")]
        [Required(ErrorMessage = "Lütfen şifreyi tekrar giriniz.")]
        [MinLength(6, ErrorMessage = "Şifre en az 6 karakter içermelidir.")]
        [MaxLength(16, ErrorMessage = "Şifre en fazla 16 karakter içerebilir.")]
        [Compare(nameof(Password), ErrorMessage ="Şifreler uyumlu değil")]
        public string RePassword { get; set; }
    }
}
