// MasterServer/Services/Abstractions/IAuthService.cs
using System.Threading.Tasks;
using System.Collections.Generic; // Для IEnumerable в RegistrationResult и EmailConfirmationResult
using MasterServer.DTOs.Auth;

namespace MasterServer.Services.Abstractions
{
    // Вспомогательные типы для результатов остаются такими же
    public record AuthResult(bool IsSuccess, string? UserId = null, string? Error = null);
    public record RegistrationResult(bool IsSuccess, string? UserId = null, IEnumerable<string>? Errors = null);
    public record PasswordResetRequestResult(bool IsSuccess, string? Error = null);
    public record PasswordResetResult(bool IsSuccess, string? Error = null, IEnumerable<string>? Errors = null);
    public record EmailConfirmationResult(bool IsSuccess, string? Error = null, IEnumerable<string>? Errors = null); // Добавил Errors на всякий случай


    public interface IAuthService
    {
        Task<AuthResult> ValidateUserCredentialsAsync(string identifier, string password);
        Task<RegistrationResult> RegisterUserAsync(RegisterRequestDto registrationData);
        Task<bool> LogoutAsync(string refreshToken);
        Task<PasswordResetRequestResult> RequestPasswordResetAsync(string email);
        Task<PasswordResetResult> ResetPasswordAsync(string userId, string code, string newPassword);
        Task<EmailConfirmationResult> ConfirmEmailAsync(string userId, string code); // Изменили: теперь принимаем userId и code
    }
}