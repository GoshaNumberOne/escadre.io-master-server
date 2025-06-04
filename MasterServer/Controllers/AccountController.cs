using MasterServer.Services.Abstractions;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations; 
using System.Threading.Tasks;
using System.Linq; // Для .Any() и string.Join()
using System.Threading.Tasks;

namespace MasterServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AccountController(IAuthService authService)
        {
            _authService = authService;
        }
        public class ResendConfirmationEmailRequestDto
        {
            [Required] // Добавим атрибут валидации
            [EmailAddress]
            public required string Email { get; set; }
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string code) // Принимаем userId и code
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return BadRequest("User ID and confirmation code are required.");
            }

            // Передаем оба параметра в сервис
            var result = await _authService.ConfirmEmailAsync(userId, code);

            if (result.IsSuccess)
            {
                // TODO: Вернуть красивую HTML страницу об успехе или редирект
                return Ok("Email confirmed successfully! You can now login.");
            }
            else
            {
                // TODO: Вернуть красивую HTML страницу об ошибке
                var errorMessages = result.Errors != null && result.Errors.Any()
                                   ? string.Join(", ", result.Errors)
                                   : result.Error ?? "Failed to confirm email.";
                return BadRequest(errorMessages);
            }
        }
        
        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequestDto request)
        {
            if (!ModelState.IsValid) // Проверка валидации DTO
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.ResendConfirmationEmailAsync(request.Email);

            if (result.IsSuccess)
            {
                return Ok(new { message = result.Message });
            }
            else
            {
                // Если RequiresUserAction (например, email уже подтвержден), это может быть не ошибка, а информация
                if (result.RequiresUserAction)
                {
                    return Conflict(new { message = result.Message }); // 409 Conflict, если email уже подтвержден
                }
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = result.Message ?? "Failed to resend confirmation email." });
            }
        }

        [HttpGet("reset-password")]
        public IActionResult ResetPassword([FromQuery] string token)
        {
             if (string.IsNullOrEmpty(token))
             {
                return BadRequest("Reset token is required.");
             }
             return Ok($"Please proceed to set a new password using token: {token}"); // Заглушка
        }
    }
}