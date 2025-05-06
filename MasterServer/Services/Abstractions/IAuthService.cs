using System.Threading.Tasks;
using MasterServer.DTOs.Auth;

namespace MasterServer.Services.Abstractions
{
    public record PasswordResetRequestResult(bool IsSuccess, string? Error = null);
    public record PasswordResetResult(bool IsSuccess, string? Error = null);
    public record EmailConfirmationResult(bool IsSuccess, string? Error = null);
    public record AuthResult(bool IsSuccess, string? UserId = null, string? Error = null);
    public record RegistrationResult(bool IsSuccess, string? UserId = null, IEnumerable<string>? Errors = null);

    public interface IAuthService
    {
        Task<PasswordResetRequestResult> RequestPasswordResetAsync(string email);
        Task<PasswordResetResult> ResetPasswordAsync(string resetToken, string newPassword);
        Task<EmailConfirmationResult> ConfirmEmailAsync(string confirmationToken);
        Task<AuthResult> ValidateUserCredentialsAsync(string identifier, string password);
        Task<RegistrationResult> RegisterUserAsync(RegisterRequestDto registrationData);
        Task<bool> LogoutAsync(string refreshToken);
    }
}