using MasterServer.DTOs.Server;

namespace MasterServer.DTOs.Auth
{
    public class LoginResponseDto
    {
        public required string AccessToken { get; set; }
        public required DateTime AccessTokenExpiration { get; set; }
        public required string RefreshToken { get; set; }
    }
}