using System.ComponentModel.DataAnnotations;

namespace DualTokenApi.Models
{
    public class ServiceKeyModel
    {
        [Required]
        public string ApiKey { get; set; }
    }
}
