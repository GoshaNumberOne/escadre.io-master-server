using System.Text.Json.Serialization; // Добавьте этот using

namespace MasterServer.DTOs.Auth
{
    public class AnonymousTokenRequestDto
    {
        [JsonPropertyName("nickname")] // Явно указываем имя JSON свойства
        public required string Nickname { get; set; } // Можете вернуть required
    }
}