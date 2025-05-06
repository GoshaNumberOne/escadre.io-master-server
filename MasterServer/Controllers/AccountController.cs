using MasterServer.Services.Abstractions;
using Microsoft.AspNetCore.Mvc;
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

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("Confirmation token is required.");
            }

            var result = await _authService.ConfirmEmailAsync(token);

            if (result.IsSuccess)
            {
                return Ok("Email confirmed successfully!");
            }
            else
            {
                return BadRequest(result.Error ?? "Failed to confirm email.");
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