using MasterServer.Services.Abstractions;
using BCryptNet = BCrypt.Net.BCrypt; 

namespace MasterServer.Services.Implementations
{
    public class BcryptPasswordHasher : IPasswordHasher
    {
        public string HashPassword(string password)
        {
            return BCryptNet.HashPassword(password);
        }

        public bool VerifyPassword(string hashedPassword, string providedPassword)
        {
            try
            {
                return BCryptNet.Verify(providedPassword, hashedPassword);
            }
            catch (BCrypt.Net.SaltParseException) 
            {
                return false;
            }
        }
    }
}