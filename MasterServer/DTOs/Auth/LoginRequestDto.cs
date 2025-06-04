using System.Text.Json.Serialization;

namespace MasterServer.DTOs.Auth
{
    

    public class LoginRequestDto
    {
        [JsonPropertyName("identifier")]
        public required string Identifier { get; set; }

        [JsonPropertyName("password")]
        public required string Password { get; set; }
    }
}