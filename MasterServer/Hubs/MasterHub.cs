using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization; 
using MasterServer.Services.Abstractions; 
using MasterServer.DTOs.Auth;          
using MasterServer.DTOs.Server;     
using MasterServer.Data;                    
using System.Security.Claims;              

namespace MasterServer.Hubs
{
    public class MasterHub : Hub
    {
        private readonly IAuthService _authService;
        private readonly ITokenService _tokenService;
        private readonly IUserService _userService;
        private readonly IGameServerManager _gameServerManager;
        private readonly AppDbContext _context; 
        private readonly IEmailService _emailService;
        public MasterHub(
            IAuthService authService,
            ITokenService tokenService,
            IUserService userService,
            IGameServerManager gameServerManager,
            AppDbContext context,
            IEmailService emailService)
        {
            Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub CONSTRUCTOR: ENTERED !!!!!!!!!!!!!!!!!"); // ВАЖНЫЙ ЛОГ
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
            _gameServerManager = gameServerManager ?? throw new ArgumentNullException(nameof(gameServerManager));
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _emailService = emailService ?? throw new ArgumentNullException(nameof(emailService));
            Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub CONSTRUCTOR: EXITED SUCCESSFULLY !!!!!!!!!!!!!!!!!"); // ВАЖНЫЙ ЛОГ
        }

        public async Task Login(LoginRequestDto credentials)
        {
            if (credentials == null || string.IsNullOrEmpty(credentials.Identifier) || string.IsNullOrEmpty(credentials.Password))
            {
                await Clients.Caller.SendAsync("LoginFailed", "Identifier and password are required.");
                return;
            }

            var authResult = await _authService.ValidateUserCredentialsAsync(credentials.Identifier, credentials.Password);

            if (!authResult.IsSuccess || authResult.UserId == null)
            {
                await Clients.Caller.SendAsync("LoginFailed", authResult.Error ?? "Invalid credentials or email not confirmed.");
                return;
            }

            var user = await _userService.FindUserByIdAsync(authResult.UserId);
            var claims = new List<Claim>();
            if (user != null)
            {
                claims.Add(new Claim(ClaimTypes.Email, user.Email));
                claims.Add(new Claim("nickname", user.Nickname));
            }

            var tokens = await _tokenService.GenerateTokensAsync(authResult.UserId, claims);

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving refresh token for user {authResult.UserId}: {ex.Message}");
                await Clients.Caller.SendAsync("LoginFailed", "Internal server error during token processing.");
                return;
            }

            var response = new LoginResponseDto
            {
                AccessToken = tokens.AccessToken,
                AccessTokenExpiration = tokens.AccessTokenExpiration,
                RefreshToken = tokens.RefreshToken, 
                UserId = authResult.UserId,
                Nickname = user.Nickname
            };
            await Clients.Caller.SendAsync("LoginSuccess", response);
        }

        public async Task Register(RegisterRequestDto registrationData)
        {
             if (registrationData == null || string.IsNullOrEmpty(registrationData.Email) || string.IsNullOrEmpty(registrationData.Password) || string.IsNullOrEmpty(registrationData.Nickname))
            {
                await Clients.Caller.SendAsync("RegistrationFailed", new List<string> { "Email, password, and nickname are required." });
                return;
            }

            var registrationResult = await _authService.RegisterUserAsync(registrationData);

            if (!registrationResult.IsSuccess)
            {
                await Clients.Caller.SendAsync("RegistrationFailed", registrationResult.Errors ?? new List<string> { "Unknown registration error." });
                return;
            }
            await Clients.Caller.SendAsync("RegistrationSuccess", "User registered successfully. Please check your email to confirm your account.");
        }

        /*public async Task<TokenResponseDto> GetAnonymousToken(AnonymousTokenRequestDto request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Nickname))
            {
                // Это будет поймано клиентом в catch (HubException ex)
                throw new HubException("Nickname is required for an anonymous token.");
            }

            try
            {
                // Этот метод в ITokenService должен возвращать что-то вроде AccessTokenInfo
                var tokenInfo = await _tokenService.GenerateAnonymousAccessTokenAsync(request.Nickname);

                if (tokenInfo == null || string.IsNullOrEmpty(tokenInfo.AccessToken))
                {
                    throw new HubException("Failed to generate anonymous access token on the server.");
                }

                var response = new TokenResponseDto
                {
                    AccessToken = tokenInfo.AccessToken,
                    AccessTokenExpiration = tokenInfo.AccessTokenExpiration,
                    NewRefreshToken = null, // Анонимный доступ обычно не имеет refresh токена
                    // UserId здесь может быть null или специальное значение, если оно есть в tokenInfo
                    // или если вы его генерируете здесь для TokenResponseDto
                };
                return response;
            }
            catch (Exception ex)
            {
                // Логирование полного исключения на сервере очень важно
                // _logger.LogError(ex, "Error generating anonymous token for nickname {Nickname}", request.Nickname);
                //Console.WriteLine($"Error in GetAnonymousToken: {ex.ToString()}"); // Временный лог, если нет ILogger
                //throw new HubException("An internal server error occurred while generating the anonymous token.", ex);
                // Если используете ILogger:
                // _logger.LogError(ex, "Error in GetAnonymousToken for nickname {Nickname}. Exception: {ExceptionDetails}", request.Nickname, ex.ToString());
                
                // Если нет ILogger под рукой, то хотя бы в консоль:
                Console.WriteLine($"!!!!!!!!!!!!!!!!! EXCEPTION IN GetAnonymousToken !!!!!!!!!!!!!!!!!");
                Console.WriteLine($"NICKNAME: {request?.Nickname}"); // Добавил вывод никнейма для контекста
                Console.WriteLine($"EXCEPTION TYPE: {ex.GetType().FullName}");
                Console.WriteLine($"MESSAGE: {ex.Message}");
                Console.WriteLine($"STACK TRACE: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"--- INNER EXCEPTION ---");
                    Console.WriteLine($"INNER EXCEPTION TYPE: {ex.InnerException.GetType().FullName}");
                    Console.WriteLine($"INNER MESSAGE: {ex.InnerException.Message}");
                    Console.WriteLine($"INNER STACK TRACE: {ex.InnerException.StackTrace}");
                }
                Console.WriteLine($"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                
                throw new HubException("An internal server error occurred while generating the anonymous token.", ex);
            }
        }*/

        // MasterHub.cs
        public async Task<string> ObtainAnonymousAccessToken() // УБРАЛИ ПАРАМЕТР, ИЗМЕНИЛИ ТИП ВОЗВРАТА ДЛЯ ПРОСТОТЫ
        {
            Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken: MINIMAL NO_PARAM METHOD ENTERED !!!!!!!!!!!!!!!!!");
            await Task.Delay(10); // Просто чтобы был await
            // return new TokenResponseDto { AccessToken = "test_token", AccessTokenExpiration = DateTime.UtcNow.AddHours(1) };
            return "Test_Token_From_Minimal_Method";
        }
        public async Task RefreshToken(RefreshTokenRequestDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.RefreshToken))
            {
                 await Clients.Caller.SendAsync("TokenRefreshFailed", "Refresh token is required.");
                 return;
            }

            var refreshResult = await _tokenService.RefreshTokenAsync(request.RefreshToken);

            if (!refreshResult.IsSuccess || refreshResult.NewAccessToken == null || refreshResult.NewAccessTokenExpiration == null)
            {
                 await Clients.Caller.SendAsync("TokenRefreshFailed", refreshResult.Error ?? "Invalid or expired refresh token.");
                 return;
            }

             var response = new TokenResponseDto
            {
                AccessToken = refreshResult.NewAccessToken,
                AccessTokenExpiration = refreshResult.NewAccessTokenExpiration.Value, 
                NewRefreshToken = refreshResult.NewRefreshToken 
            };
            await Clients.Caller.SendAsync("TokenRefreshed", response);
        }

        public async Task RequestPasswordReset(string email)
        {
             if (string.IsNullOrEmpty(email))
             {
                 await Clients.Caller.SendAsync("PasswordResetRequested", "If an account with that email exists, a password reset link has been sent.");
                 return;
             }
             await _authService.RequestPasswordResetAsync(email);
             await Clients.Caller.SendAsync("PasswordResetRequested", "If an account with that email exists, a password reset link has been sent.");
        }

        public async Task ResetPassword(string userId, string code, string newPassword) // Принимаем все три
        {
            // Базовая валидация здесь
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code) || string.IsNullOrEmpty(newPassword))
            {
                await Clients.Caller.SendAsync("PasswordResetFailed", "User ID, reset code, and new password are required.");
                return;
            }
            // Передаем все три параметра в сервис
            var result = await _authService.ResetPasswordAsync(userId, code, newPassword);
            if (result.IsSuccess)
            {
                await Clients.Caller.SendAsync("PasswordResetSuccess", "Password has been reset successfully. Please login with your new password.");
            }
            else
            {
                var errorMessages = result.Errors != null && result.Errors.Any()
                                ? string.Join(", ", result.Errors)
                                : result.Error ?? "Failed to reset password.";
                await Clients.Caller.SendAsync("PasswordResetFailed", errorMessages);
            }
        }

        public async Task Logout(LogoutRequestDto request)
        {
             if (request == null || string.IsNullOrEmpty(request.RefreshToken))
             {
                  await Clients.Caller.SendAsync("LogoutFailed", "Refresh token is required.");
                  return;
             }
             await _authService.LogoutAsync(request.RefreshToken);
             await Clients.Caller.SendAsync("LoggedOut", "Successfully logged out.");
        }

        public async Task ConfirmEmail(string userId, string code) // Теперь принимаем два параметра
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code)) // Проверяем оба
            {
                await Clients.Caller.SendAsync("EmailConfirmationFailed", "User ID and confirmation code are required.");
                return;
            }
            // Передаем оба параметра в сервис
            var result = await _authService.ConfirmEmailAsync(userId, code);
            if (result.IsSuccess)
            {
                await Clients.Caller.SendAsync("EmailConfirmationSuccess", "Email confirmed successfully. You can now login.");
            }
            else
            {
                // Передаем ошибки из результата, если они есть
                var errorMessages = result.Errors != null && result.Errors.Any()
                                    ? string.Join(", ", result.Errors)
                                    : result.Error ?? "Failed to confirm email.";
                await Clients.Caller.SendAsync("EmailConfirmationFailed", errorMessages);
            }
        }

        [Authorize] 
        public async Task GetServerList(string? regionFilter = null)
        {
            var servers = await _gameServerManager.GetAvailableServersAsync(regionFilter);
            await Clients.Caller.SendAsync("ReceiveServerList", servers ?? new List<GameServerInfoDto>());
        }

        [Authorize] 
        public async Task RequestMatchmaking(string gameMode)
        {
            var userId = Context.UserIdentifier;
            if (userId == null)
            {
                await Clients.Caller.SendAsync("MatchmakingFailed", "Authentication error.");
                Context.Abort();
                return;
            }

             if (string.IsNullOrEmpty(gameMode))
            {
                await Clients.Caller.SendAsync("MatchmakingFailed", "Game mode is required.");
                return;
            }

            Console.WriteLine($"User {userId} (Connection: {Context.ConnectionId}) requested matchmaking for mode '{gameMode}'.");

            await Clients.Caller.SendAsync("MatchmakingStatus", "Searching for match...");
        }

        public override async Task OnConnectedAsync()
        {
            var userId = Context.UserIdentifier;
            var connectionId = Context.ConnectionId;
            Console.WriteLine($"Client connected: {connectionId}. UserID (from token): {userId ?? "N/A"}");

            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
             var userId = Context.UserIdentifier;
             var connectionId = Context.ConnectionId;
             if (exception != null)
             {
                 Console.WriteLine($"Client disconnected: {connectionId}. UserID: {userId ?? "N/A"}. Reason: {exception.Message}");
             }
             else
             {
                 Console.WriteLine($"Client disconnected: {connectionId}. UserID: {userId ?? "N/A"}. Reason: Connection terminated.");
             }

            await base.OnDisconnectedAsync(exception);
        }
    }

    public class LogoutRequestDto
    {
         public required string RefreshToken { get; set; }
    }
}