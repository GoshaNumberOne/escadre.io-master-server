using System.ComponentModel.DataAnnotations; 

namespace MasterServer.DTOs.Auth
{
    public class RegisterRequestDto
    {
        [EmailAddress]
        public required string Email { get; set; }

        [MinLength(6)] 
        public required string Password { get; set; }
        public required string Nickname { get; set; }
    }
}