using System.Text.Json.Serialization;
using System.ComponentModel.DataAnnotations; // Если используете атрибуты валидации здесь

namespace MasterServer.DTOs.Auth
{
    
    public class RegisterRequestDto
    {
        [JsonPropertyName("email")]
        [EmailAddress] // Этот атрибут используется ASP.NET Core для валидации модели, если бы это был HTTP эндпоинт
        public required string Email { get; set; }

        [JsonPropertyName("password")]
        [MinLength(6)] 
        public required string Password { get; set; }

        [JsonPropertyName("nickname")]
        public required string Nickname { get; set; }
    }
}