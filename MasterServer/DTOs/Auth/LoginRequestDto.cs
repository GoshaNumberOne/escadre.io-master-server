namespace MasterServer.DTOs.Auth
{
    public class LoginRequestDto
    {
        public required string Identifier { get; set; }
        public required string Password { get; set; }
    }
}