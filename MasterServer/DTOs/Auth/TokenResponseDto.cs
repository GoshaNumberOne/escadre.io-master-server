namespace MasterServer.DTOs.Auth
{
    public class TokenResponseDto
    {
        public required string AccessToken { get; set; }
        public required DateTime AccessTokenExpiration { get; set; }
        public string? NewRefreshToken { get; set; }
    }
}