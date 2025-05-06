using MasterServer.Data;
using MasterServer.Data.Entities; 
using MasterServer.DTOs.Auth;
using MasterServer.Services.Abstractions;
using Microsoft.EntityFrameworkCore; 
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace MasterServer.Services.Implementations
{
    public class AuthService : IAuthService
    {
        private readonly IUserService _userService;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITokenService _tokenService;
        private readonly AppDbContext _context;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration; 

        public AuthService(
            IUserService userService,
            IPasswordHasher passwordHasher,
            ITokenService tokenService,
            AppDbContext context,
            IEmailService emailService,
            IConfiguration configuration)
        {
            _userService = userService;
            _passwordHasher = passwordHasher;
            _tokenService = tokenService;
            _context = context;
            _emailService = emailService; 
            _configuration = configuration; 
        }

        public async Task<AuthResult> ValidateUserCredentialsAsync(string identifier, string password)
        {
            var user = await _userService.FindUserByIdentifierAsync(identifier);
            if (user == null)
            {
                return new AuthResult(false, Error: "User not found.");
            }

             if (!user.IsEmailConfirmed)
            {
                return new AuthResult(false, Error: "Email address not confirmed.");
            }

            if (!_passwordHasher.VerifyPassword(user.PasswordHash, password))
            {
                return new AuthResult(false, Error: "Invalid password.");
            }

            return new AuthResult(true, UserId: user.Id);
        }

        public async Task<RegistrationResult> RegisterUserAsync(RegisterRequestDto registrationData)
        {
            if (await _userService.CheckIfUserExistsAsync(registrationData.Email))
            { return new RegistrationResult(false, Errors: new[] { "Email already exists." }); }
            if (await _userService.CheckIfUserExistsAsync(registrationData.Nickname))
            { return new RegistrationResult(false, Errors: new[] { "Nickname already exists." }); }

            var hashedPassword = _passwordHasher.HashPassword(registrationData.Password);

            var user = new User
            {
                Email = registrationData.Email,
                Nickname = registrationData.Nickname,
                PasswordHash = hashedPassword,
                IsEmailConfirmed = false, 
                EmailConfirmationToken = GenerateSecureToken(),
                EmailConfirmationTokenExpiry = DateTime.UtcNow.AddHours(24) 
            };

            _context.Users.Add(user);
            var initialStats = new PlayerStat { UserId = user.Id }; 
            _context.PlayerStats.Add(initialStats);

            try
            {
                await _context.SaveChangesAsync();
                var confirmationLink = $"[Link Placeholder]?token={user.EmailConfirmationToken}"; // TODO: поменять

                await _emailService.SendEmailAsync(
                    user.Email,
                    "Confirm your email address",
                    $"Please confirm your email by clicking this link: <a href='{confirmationLink}'>Confirm Email</a> or use this token: {user.EmailConfirmationToken}"
                );

                return new RegistrationResult(true, UserId: user.Id);
            }
            catch (DbUpdateException ex)
            {
                Console.WriteLine($"Error creating user: {ex.Message}");
                return new RegistrationResult(false, Errors: new[] { "Failed to create user." });
            }
            catch (Exception emailEx) 
            {
                 Console.WriteLine($"Error sending confirmation email: {emailEx.Message}");
                 return new RegistrationResult(true, UserId: user.Id);
            }
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            await _tokenService.InvalidateRefreshTokenAsync(refreshToken);
            return true;
        }

        public async Task<PasswordResetRequestResult> RequestPasswordResetAsync(string email)
        {
            var user = await _userService.FindUserByIdentifierAsync(email);
            if (user == null)
            {
                return new PasswordResetRequestResult(true);
            }
            user.PasswordResetToken = GenerateSecureToken();
            user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1);
            _context.Users.Update(user);

            try
            {
                await _context.SaveChangesAsync();
                var resetLink = $"[Reset Link Placeholder]?token={user.PasswordResetToken}"; // TODO: поменять

                await _emailService.SendEmailAsync(
                    user.Email,
                    "Password Reset Request",
                    $"To reset your password, click this link: <a href='{resetLink}'>Reset Password</a> or use this token: {user.PasswordResetToken}. If you didn't request this, please ignore this email."
                );

                return new PasswordResetRequestResult(true);
            }
             catch (Exception ex)
            {
                Console.WriteLine($"Error requesting password reset for {email}: {ex.Message}");
                return new PasswordResetRequestResult(true);
            }
        }

        public async Task<PasswordResetResult> ResetPasswordAsync(string resetToken, string newPassword)
        {
             if (string.IsNullOrEmpty(resetToken) || string.IsNullOrEmpty(newPassword) || newPassword.Length < 6)
             {
                  return new PasswordResetResult(false, Error: "Invalid token or password.");
             }

             var user = await _context.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == resetToken);

             if (user == null || user.PasswordResetTokenExpiry < DateTime.UtcNow)
             {
                  return new PasswordResetResult(false, Error: "Invalid or expired reset token.");
             }

             user.PasswordHash = _passwordHasher.HashPassword(newPassword);
             user.PasswordResetToken = null;
             user.PasswordResetTokenExpiry = null;

             _context.Users.Update(user);
             await _context.SaveChangesAsync();

             return new PasswordResetResult(true);
        }

        public async Task<EmailConfirmationResult> ConfirmEmailAsync(string confirmationToken)
        {
             if (string.IsNullOrEmpty(confirmationToken))
             {
                 return new EmailConfirmationResult(false, Error: "Invalid confirmation token.");
             }

             var user = await _context.Users.FirstOrDefaultAsync(u => u.EmailConfirmationToken == confirmationToken);

             if (user == null)
             {
                  return new EmailConfirmationResult(false, Error: "Invalid confirmation token.");
             }

             if (user.IsEmailConfirmed)
             {
                  return new EmailConfirmationResult(true);
             }

             if (user.EmailConfirmationTokenExpiry < DateTime.UtcNow)
             {
                 // TODO: запрос нового письма
                 return new EmailConfirmationResult(false, Error: "Confirmation token expired.");
             }

             user.IsEmailConfirmed = true;
             user.EmailConfirmationToken = null;
             user.EmailConfirmationTokenExpiry = null;

             _context.Users.Update(user);
             await _context.SaveChangesAsync();

             return new EmailConfirmationResult(true);
        }

         private string GenerateSecureToken()
         {
             using var rng = RandomNumberGenerator.Create();
             var tokenBytes = new byte[32];
             rng.GetBytes(tokenBytes);
             return Convert.ToBase64String(tokenBytes)
                           .Replace('+', '-')
                           .Replace('/', '_')
                           .TrimEnd('=');
         }
    }
}