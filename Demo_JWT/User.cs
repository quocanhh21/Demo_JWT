using System.ComponentModel.DataAnnotations;

namespace Demo_JWT
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(50)]
        public string UserName { get; set; }

        [Required]
        [MaxLength(50)]
        public string Password { get; set; }

        public string FullName { get; set; }

        public string Email { get; set; }

    }
}
