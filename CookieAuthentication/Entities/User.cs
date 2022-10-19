using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CookieAuthentication.Entities
{
    [Table("Users")]
    public class User
    {
        [Key]
        public Guid Id { get; set; }

        [StringLength(50,ErrorMessage = "Kullanıcı adı en fazla 50 karakter içerebilir.")]
        public string? FullName { get; set; }

        [Required]
        [StringLength(30)]
        public string Username { get; set; }

        [Required(ErrorMessage ="Lütfen yeni şifre alanını boş bırakmayınız.")]
        [StringLength(100)]
        public string Password { get; set; }
        public bool Locked { get; set; } = false;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        [Required]
        [StringLength(50)]
        public string Role { get; set; } = "user";
    }
}
