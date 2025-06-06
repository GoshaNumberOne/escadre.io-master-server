using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization; 
using MasterServer.Services.Abstractions; 
using MasterServer.DTOs.Auth;          
using MasterServer.DTOs.Server;     
using MasterServer.Data;                    
using System.Security.Claims;           
using System.Text.Json;   
using System.Linq;
using MasterServer.DTOs;
using Microsoft.EntityFrameworkCore;

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

        public async Task Login(JsonElement requestPayload) // Изменяем тип параметра
        {
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): METHOD ENTERED. !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): Payload Kind: {requestPayload.ValueKind} !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): Payload RawText: {requestPayload.GetRawText()} !!!!!!!!!!!!!!!!!");

            LoginRequestDto credentials = null;

            // Обработка случая, когда клиент шлет массив с одним элементом
            if (requestPayload.ValueKind == JsonValueKind.Array && requestPayload.GetArrayLength() > 0)
            {
                JsonElement firstElement = requestPayload.EnumerateArray().FirstOrDefault();
                if (firstElement.ValueKind == JsonValueKind.Object)
                {
                    try
                    {
                        credentials = firstElement.Deserialize<LoginRequestDto>(new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true,
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase // Важно для консистентности
                        });
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): Deserialized from first array element. Identifier: '{credentials?.Identifier}' !!!!!!!!!!!!!!!!!");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): FAILED to deserialize first array element: {ex.ToString()} !!!!!!!!!!!!!!!!!");
                        await Clients.Caller.SendAsync("LoginFailed", "Invalid request format."); // Отправляем ошибку клиенту
                        return;
                    }
                }
            }
            else if (requestPayload.ValueKind == JsonValueKind.Object) // Если клиент вдруг отправит правильно
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): Payload was an OBJECT directly. !!!!!!!!!!!!!!!!!");
                try
                {
                    credentials = requestPayload.Deserialize<LoginRequestDto>(new JsonSerializerOptions {
                        PropertyNameCaseInsensitive = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): FAILED to deserialize object payload: {ex.ToString()} !!!!!!!!!!!!!!!!!");
                    await Clients.Caller.SendAsync("LoginFailed", "Invalid request format.");
                    return;
                }
            }

            if (credentials == null || string.IsNullOrEmpty(credentials.Identifier) || string.IsNullOrEmpty(credentials.Password))
            {
                Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): Invalid login data after parsing. !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("LoginFailed", "Identifier and password are required.");
                return;
            }

            // Вызываем существующий сервис для валидации и генерации токенов
            var authResult = await _authService.ValidateUserCredentialsAsync(credentials.Identifier, credentials.Password);

            if (!authResult.IsSuccess || string.IsNullOrEmpty(authResult.UserId)) // Проверяем и UserId
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): AuthService validation failed. Error: {authResult.Error} !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("LoginFailed", authResult.Error ?? "Invalid credentials or email not confirmed.");
                return;
            }

            // Если валидация успешна, генерируем токены
            var user = await _userService.FindUserByIdAsync(authResult.UserId); // Получаем пользователя для Nickname
            if (user == null) { // Маловероятно, если ValidateUserCredentialsAsync вернул UserId, но проверим
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): User not found by ID {authResult.UserId} after successful validation. !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("LoginFailed", "User data inconsistency error.");
                return;
            }

            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Email, user.Email)); // Предполагаем, что Email есть у User
            claims.Add(new Claim("nickname", user.Nickname));    // Nickname из сущности User

            var tokens = await _tokenService.GenerateTokensAsync(authResult.UserId, claims);
            
            // Важно: AuthService или TokenService должны сохранять RefreshToken в БД.
            // Если JwtTokenService.GenerateTokensAsync это делает и вызывает SaveChanges, то хорошо.
            // Если нет, то здесь нужно await _context.SaveChangesAsync();
            // В вашем JwtTokenService.GenerateTokensAsync нет SaveChanges, а в RefreshTokenAsync есть.
            // Давайте добавим SaveChanges здесь, чтобы быть уверенными.
            try
            {
                await _context.SaveChangesAsync(); // Сохраняем RefreshToken, добавленный в GenerateTokensAsync
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): Refresh token for user {authResult.UserId} saved. !!!!!!!!!!!!!!!!!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): CRITICAL - Error saving refresh token for user {authResult.UserId}: {ex.Message} !!!!!!!!!!!!!!!!!");
                // Это серьезная ошибка, пользователь не сможет обновлять токен
                await Clients.Caller.SendAsync("LoginFailed", "Internal server error during token processing.");
                return;
            }

            var response = new LoginResponseDto
            {
                AccessToken = tokens.AccessToken,
                AccessTokenExpiration = tokens.AccessTokenExpiration,
                RefreshToken = tokens.RefreshToken,
                UserId = authResult.UserId,
                Nickname = user.Nickname // Nickname из сущности User
            };

            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Login (JsonElement): User {user.Email} logged in. Sending LoginSuccess. !!!!!!!!!!!!!!!!!");
            await Clients.Caller.SendAsync("LoginSuccess", response);
        }

        public async Task Register(JsonElement requestPayload) // Изменяем тип параметра
        {
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): METHOD ENTERED. !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): Payload Kind: {requestPayload.ValueKind} !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): Payload RawText: {requestPayload.GetRawText()} !!!!!!!!!!!!!!!!!");

            RegisterRequestDto registrationData = null;

            if (requestPayload.ValueKind == JsonValueKind.Array && requestPayload.GetArrayLength() > 0)
            {
                JsonElement firstElement = requestPayload.EnumerateArray().FirstOrDefault();
                if (firstElement.ValueKind == JsonValueKind.Object)
                {
                    try
                    {
                        registrationData = firstElement.Deserialize<RegisterRequestDto>(new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true,
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                        });
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): Deserialized from first array element. Email: '{registrationData?.Email}' !!!!!!!!!!!!!!!!!");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): FAILED to deserialize first array element: {ex.ToString()} !!!!!!!!!!!!!!!!!");
                        await Clients.Caller.SendAsync("RegistrationFailed", new List<string> { "Invalid request format." });
                        return;
                    }
                }
            }
            else if (requestPayload.ValueKind == JsonValueKind.Object) // На случай, если клиент вдруг начнет слать правильно
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): Payload was an OBJECT directly. !!!!!!!!!!!!!!!!!");
                try
                {
                    registrationData = requestPayload.Deserialize<RegisterRequestDto>(new JsonSerializerOptions {
                        PropertyNameCaseInsensitive = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): FAILED to deserialize object payload: {ex.ToString()} !!!!!!!!!!!!!!!!!");
                    await Clients.Caller.SendAsync("RegistrationFailed", new List<string> { "Invalid request format." });
                    return;
                }
            }

            if (registrationData == null || string.IsNullOrEmpty(registrationData.Email) || string.IsNullOrEmpty(registrationData.Password) || string.IsNullOrEmpty(registrationData.Nickname))
            {
                Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): Invalid registration data after parsing. !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("RegistrationFailed", new List<string> { "Email, password, and nickname are required." });
                return;
            }

            // Вызываем существующий сервис регистрации
            var registrationResult = await _authService.RegisterUserAsync(registrationData);

            if (!registrationResult.IsSuccess)
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): AuthService registration failed. Errors: {string.Join(", ", registrationResult.Errors ?? new List<string>())} !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("RegistrationFailed", registrationResult.Errors ?? new List<string> { "Unknown registration error." });
                return;
            }

            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.Register (JsonElement): User {registrationData.Email} registered by AuthService. Sending success to client. !!!!!!!!!!!!!!!!!");
            await Clients.Caller.SendAsync("RegistrationSuccess", "User registered successfully. Please check your email to confirm your account.");
        }

        public async Task<TokenResponseDto> GetAnonymousToken(JsonElement requestPayload)
        {
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): METHOD ENTERED. !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): Payload Kind: {requestPayload.ValueKind} !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): Payload RawText: {requestPayload.GetRawText()} !!!!!!!!!!!!!!!!!");

            AnonymousTokenRequestDto request = null;
            string nickname = null;

            // ПРОВЕРЯЕМ, ЧТО ЭТО МАССИВ И БЕРЕМ ПЕРВЫЙ ЭЛЕМЕНТ
            if (requestPayload.ValueKind == JsonValueKind.Array && requestPayload.GetArrayLength() > 0)
            {
                JsonElement firstElement = requestPayload.EnumerateArray().FirstOrDefault();
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): First element Kind: {firstElement.ValueKind} !!!!!!!!!!!!!!!!!");
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): First element RawText: {firstElement.GetRawText()} !!!!!!!!!!!!!!!!!");

                if (firstElement.ValueKind == JsonValueKind.Object)
                {
                    try
                    {
                        // Десериализуем ПЕРВЫЙ ЭЛЕМЕНТ МАССИВА в наш DTO
                        request = firstElement.Deserialize<AnonymousTokenRequestDto>(new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true,
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                        });
                        nickname = request?.Nickname;
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): Deserialized from first array element. Nickname: '{nickname ?? "NULL"}' !!!!!!!!!!!!!!!!!");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): FAILED to deserialize first array element: {ex.ToString()} !!!!!!!!!!!!!!!!!");
                        throw new HubException("Failed to deserialize first array element payload.", ex);
                    }
                }
            }
            else if (requestPayload.ValueKind == JsonValueKind.Object) // На случай, если клиент вдруг начнет слать правильно
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): Payload was an OBJECT directly. !!!!!!!!!!!!!!!!!");
                // ... (код для десериализации объекта, как раньше) ...
                try
                    {
                        request = requestPayload.Deserialize<AnonymousTokenRequestDto>(new JsonSerializerOptions {
                            PropertyNameCaseInsensitive = true,
                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                        });
                        nickname = request?.Nickname;
                    }
                    catch (Exception ex) { /* ... */ throw; }
            }


            if (string.IsNullOrWhiteSpace(nickname))
            {
                Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): Nickname is required, throwing HubException. !!!!!!!!!!!!!!!!!");
                throw new HubException("Nickname is required and could not be extracted from payload (processed as JsonElement).");
            }

            try
            {
                Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): TRY BLOCK ENTERED with Nickname: " + nickname + " !!!!!!!!!!!!!!!!!");
                var tokenInfo = await _tokenService.GenerateAnonymousAccessTokenAsync(nickname);
                var response = new TokenResponseDto { AccessToken = tokenInfo.AccessToken, AccessTokenExpiration = tokenInfo.AccessTokenExpiration, NewRefreshToken = null };
                Console.WriteLine("!!!!!!!!!!!!!!!!! MasterHub.GetAnonymousToken (JsonElement Array Fix): Returning response. !!!!!!!!!!!!!!!!!");
                return response;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! EXCEPTION IN TOKEN GENERATION (JsonElement Array Fix): {ex.ToString()} !!!!!!!!!!!!!!!!!");
                throw new HubException("Error generating token (processed as JsonElement).", ex);
            }
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

       public async Task RequestPasswordReset(JsonElement payloadElement) // Изменили тип параметра
        {
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): METHOD ENTERED !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): Payload Kind: {payloadElement.ValueKind} !!!!!!!!!!!!!!!!!");
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): Payload RawText: {payloadElement.GetRawText()} !!!!!!!!!!!!!!!!!");

            string email = null;

            // Проверяем, пришел ли массив, и берем первый элемент (который должен быть строкой email)
            if (payloadElement.ValueKind == JsonValueKind.Array && payloadElement.GetArrayLength() > 0)
            {
                JsonElement emailElement = payloadElement.EnumerateArray().FirstOrDefault();
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): First element Kind: {emailElement.ValueKind} !!!!!!!!!!!!!!!!!");
                if (emailElement.ValueKind == JsonValueKind.String)
                {
                    email = emailElement.GetString();
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): Extracted email from array: '{email ?? "NULL"}' !!!!!!!!!!!!!!!!!");
                }
                else
                {
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): First element in array was NOT a STRING. Kind: {emailElement.ValueKind} !!!!!!!!!!!!!!!!!");
                }
            }
            // На случай, если клиент вдруг начнет слать просто строку (маловероятно, судя по ошибке)
            else if (payloadElement.ValueKind == JsonValueKind.String)
            {
                email = payloadElement.GetString();
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): Extracted email directly as string: '{email ?? "NULL"}' !!!!!!!!!!!!!!!!!");
            }


            if (string.IsNullOrWhiteSpace(email))
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): Email is NULL or WhiteSpace. Sending generic response. !!!!!!!!!!!!!!!!!");
                // Все равно отправляем "успешный" ответ, чтобы не раскрывать существование email
                await Clients.Caller.SendAsync("PasswordResetRequested", "If an account with that email exists, a password reset link has been sent.");
                return;
            }

            try
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.RequestPasswordReset (JsonElement): Calling AuthService for email: {email} !!!!!!!!!!!!!!!!!");
                await _authService.RequestPasswordResetAsync(email); // AuthService ожидает string email
                                                                // AuthService сам отправит письмо
                await Clients.Caller.SendAsync("PasswordResetRequested", "If an account with that email exists, a password reset link has been sent.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! EXCEPTION in RequestPasswordReset for email {email}: {ex.ToString()} !!!!!!!!!!!!!!!!!");
                // Клиенту все равно отправляем общее сообщение в случае ошибки, чтобы не раскрывать детали
                await Clients.Caller.SendAsync("PasswordResetRequested", "If an account with that email exists, a password reset link has been sent.");
            }
        }

        public async Task ResetPassword(JsonElement payloadElement) // Принимает один JsonElement
        {
            Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.ResetPassword (JsonElement): METHOD ENTERED. Payload RawText: {payloadElement.GetRawText()} !!!!!!!!!!!!!!!!!");
            string userId = null;
            string code = null;
            string newPassword = null;

            if (payloadElement.ValueKind == JsonValueKind.Array && payloadElement.GetArrayLength() == 3)
            {
                var argsArray = payloadElement.EnumerateArray().ToList();
                if (argsArray[0].ValueKind == JsonValueKind.String) userId = argsArray[0].GetString();
                if (argsArray[1].ValueKind == JsonValueKind.String) code = argsArray[1].GetString();
                if (argsArray[2].ValueKind == JsonValueKind.String) newPassword = argsArray[2].GetString();
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.ResetPassword (JsonElement): Extracted: userId='{userId}', code='{code}', newPassword='{newPassword?.Length > 0}' !!!!!!!!!!!!!!!!!");
            }
            else
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.ResetPassword (JsonElement): Payload was not an array of 3 elements. Kind: {payloadElement.ValueKind} !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("PasswordResetFailed", "Invalid request format.");
                return;
            }

            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code) || string.IsNullOrEmpty(newPassword))
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! MasterHub.ResetPassword (JsonElement): One or more params are missing after extraction. !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("PasswordResetFailed", "User ID, reset code, and new password are required.");
                return;
            }

            try
            {
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
            catch (Exception ex)
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! EXCEPTION in ResetPassword: {ex.ToString()} !!!!!!!!!!!!!!!!!");
                await Clients.Caller.SendAsync("PasswordResetFailed", "An internal error occurred while resetting password.");
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

        // MasterHub.cs
        [Authorize]
        public async Task<PlayerStatsDto> GetMyStats()
        {
            Console.WriteLine("!!!!!!!!!!!!!!!!! GetMyStats: METHOD ENTERED !!!!!!!!!!!!!!!!!");
            var userId = Context.UserIdentifier;
            Console.WriteLine($"!!!!!!!!!!!!!!!!! GetMyStats: UserIdentifier from Context: '{userId ?? "NULL"}' !!!!!!!!!!!!!!!!!");

            if (string.IsNullOrEmpty(userId))
            {
                Console.WriteLine("!!!!!!!!!!!!!!!!! GetMyStats: UserIdentifier is NULL or Empty! Throwing HubException. !!!!!!!!!!!!!!!!!");
                throw new HubException("User not authenticated or UserIdentifier missing.");
            }

            try
            {
                var user = await _userService.FindUserByIdAsync(userId);
                if (user == null)
                {
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! GetMyStats: User NOT FOUND in DB for UserId: {userId}! Throwing HubException. !!!!!!!!!!!!!!!!!");
                    throw new HubException("User not found in database.");
                }
                Console.WriteLine($"!!!!!!!!!!!!!!!!! GetMyStats: User found: {user.UserName}, Nickname: {user.Nickname} !!!!!!!!!!!!!!!!!");

                var playerStat = await _context.PlayerStats
                                        .AsNoTracking() // Добавляем AsNoTracking, если не собираемся изменять статистику здесь
                                        .FirstOrDefaultAsync(ps => ps.UserId == userId);

                if (playerStat == null)
                {
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! GetMyStats: PlayerStat NOT FOUND for UserId: {userId}. Returning default stats. !!!!!!!!!!!!!!!!!");
                    return new PlayerStatsDto
                    {
                        Nickname = user.Nickname, // Nickname берем из user, так как он точно есть
                        Kills = 0,
                        Deaths = 0,
                        PlayTime = "00:00:00",
                        KDRatio = 0
                    };
                }
                Console.WriteLine($"!!!!!!!!!!!!!!!!! GetMyStats: PlayerStat FOUND: Kills={playerStat.Kills}, Deaths={playerStat.Deaths}, PlayTime={playerStat.PlayTime} !!!!!!!!!!!!!!!!!");

                float kdRatio = (playerStat.Deaths > 0) ? (float)playerStat.Kills / playerStat.Deaths : playerStat.Kills;
                var statsDto = new PlayerStatsDto
                {
                    Nickname = user.Nickname,
                    Kills = playerStat.Kills,
                    Deaths = playerStat.Deaths,
                    PlayTime = playerStat.PlayTime.ToString(@"hh\:mm\:ss"),
                    KDRatio = kdRatio
                };
                Console.WriteLine("!!!!!!!!!!!!!!!!! GetMyStats: Returning PlayerStatsDto SUCCESSFULLY. !!!!!!!!!!!!!!!!!");
                return statsDto;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! EXCEPTION in GetMyStats for UserId: {userId} !!!!!!!!!!!!!!!!!");
                Console.WriteLine($"EXCEPTION_TYPE: {ex.GetType().FullName}");
                Console.WriteLine($"MESSAGE: {ex.Message}");
                Console.WriteLine($"STACK_TRACE: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"--- INNER_EXCEPTION ---");
                    Console.WriteLine($"INNER_EXCEPTION_TYPE: {ex.InnerException.GetType().FullName}");
                    Console.WriteLine($"INNER_MESSAGE: {ex.InnerException.Message}");
                    Console.WriteLine($"INNER_STACK_TRACE: {ex.InnerException.StackTrace}");
                }
                Console.WriteLine($"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                throw new HubException("An error occurred while retrieving player stats.", ex); // Перебрасываем с деталями
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