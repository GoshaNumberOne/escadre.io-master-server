// MasterServer/Services/Implementations/AuthService.cs
using Microsoft.AspNetCore.Identity; // Для UserManager, SignInManager
using Microsoft.Extensions.Configuration; // Для IConfiguration
using MasterServer.Data;
using MasterServer.Data.Entities;
using MasterServer.DTOs.Auth;
using MasterServer.Services.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using Microsoft.EntityFrameworkCore; // Для WebUtility.UrlEncode

namespace MasterServer.Services.Implementations
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        // SignInManager нужен, если используешь options.SignIn.RequireConfirmedEmail = true;
        // и для вызова CheckPasswordSignInAsync, который проверяет и пароль, и статус аккаунта
        private readonly SignInManager<User> _signInManager;
        private readonly ITokenService _tokenService; // Для генерации JWT после успешного логина
        private readonly IEmailService _emailService;
        private readonly AppDbContext _context; // Для RefreshToken и PlayerStat
        private readonly IConfiguration _configuration; // Для формирования URL в письмах

        public AuthService(
            UserManager<User> userManager,
            SignInManager<User> signInManager, // Добавь, если используется
            ITokenService tokenService,
            IEmailService emailService,
            AppDbContext context,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager; // Сохраняем
            _tokenService = tokenService;
            _emailService = emailService;
            _context = context;
            _configuration = configuration;
        }

        public async Task<AuthResult> ValidateUserCredentialsAsync(string identifier, string password)
        {
            // Ищем пользователя по Email или UserName (стандартное поле Identity)
            // Предположим, что identifier может быть либо Email, либо UserName/Nickname
            var user = await _userManager.FindByEmailAsync(identifier);
            if (user == null)
            {
                // Если не нашли по Email, попробуем найти по UserName
                // (Если Nickname должен быть UserName, это нужно учесть при регистрации)
                user = await _userManager.FindByNameAsync(identifier);
            }

            if (user == null)
            {
                return new AuthResult(false, Error: "Пользователь не найден.");
            }

            // CheckPasswordSignInAsync проверяет пароль, а также флаги (IsEmailConfirmed, IsLockedOut и т.д.)
            // lockoutOnFailure: true - будет увеличивать счетчик неудачных попыток и блокировать пользователя
            var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                return new AuthResult(true, UserId: user.Id);
            }
            if (result.IsNotAllowed) // Например, Email не подтвержден (если options.SignIn.RequireConfirmedEmail = true)
            {
                return new AuthResult(false, Error: "Вход в систему не разрешен. Пожалуйста, подтвердите свою электронную почту или проверьте состояние учетной записи.");
            }
            if (result.IsLockedOut)
            {
                return new AuthResult(false, Error: "Учетная запись заблокирована из-за слишком большого количества неудачных попыток входа.");
            }
            return new AuthResult(false, Error: "Неверный пароль."); // Общая ошибка для неверного пароля
        }

        public async Task<RegistrationResult> RegisterUserAsync(RegisterRequestDto registrationData)
        {
            // Если нет поля NormalizedNickname, то можно так (но это может быть медленнее и зависит от настроек БД):
            var existingUserByNickname = await _context.Users
                .FirstOrDefaultAsync(u => u.Nickname.ToUpper() == registrationData.Nickname.ToUpper());


            if (existingUserByNickname != null)
            {
                // Используем ваш RussianIdentityErrorDescriber или просто строку
                // Чтобы использовать ErrorDescriber, нужно его экземпляр или передать IdentityError[]
                // Проще пока так:
                return new RegistrationResult(false, Errors: new List<string> { "Этот никнейм уже используется. Пожалуйста, выберите другой." });
            }

            var user = new User
            {
                UserName = registrationData.Email, // Или registrationData.Nickname, если он должен быть уникальным и использоваться для входа
                Email = registrationData.Email,
                Nickname = registrationData.Nickname,
                CreatedAt = DateTime.UtcNow
                //IsEmailConfirmed будет false по умолчанию
            };

            // UserManager сам хеширует пароль
            var result = await _userManager.CreateAsync(user, registrationData.Password);

            if (!result.Succeeded)
            {
                return new RegistrationResult(false, Errors: result.Errors.Select(e => e.Description));
            }

            // Создаем начальную статистику для нового пользователя
            var initialStats = new PlayerStat { UserId = user.Id };
            _context.PlayerStats.Add(initialStats);
            // Сохраняем и пользователя (через UserManager) и статистику (через DbContext)
            // UserManager.CreateAsync уже вызывает SaveChanges, если используется EF Store.
            // Но для статистики нужно вызвать отдельно или убедиться, что UserManager настроен на тот же DbContext instance.
            // Безопаснее вызвать SaveChanges здесь для статистики.
            try
            {
                 await _context.SaveChangesAsync(); // Сохраняем статистику
            }
            catch (Exception ex)
            {
                // Если не удалось сохранить статистику, нужно решить, что делать.
                // Возможно, удалить пользователя или залогировать и продолжить.
                 Console.WriteLine($"Error saving initial stats for user {user.Id}: {ex.Message}");
                 // Пока что игнорируем ошибку статистики, но пользователь создан.
            }


            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedCode = WebUtility.UrlEncode(code);

            // Получаем базовый URL сервера из конфигурации
            string? serverBaseUrl = _configuration["Application:ServerBaseUrl"];
            if (string.IsNullOrEmpty(serverBaseUrl))
            {
                // Логируем предупреждение или ошибку, если URL не настроен
                Console.WriteLine("Warning: Application:ServerBaseUrl is not configured in appsettings.json. Using default localhost:5076 for callback URL.");
                serverBaseUrl = "http://localhost:5076"; // Запасной вариант, но лучше настроить
            }

            var callbackUrl = $"{serverBaseUrl}/api/Account/confirm-email?userId={user.Id}&code={encodedCode}";

            try
            {
                string emailBody = $"Please confirm your account by clicking this link: <a href='{callbackUrl}'>Confirm Account</a><br/>Or copy and paste this URL into your browser: {callbackUrl}";
                await _emailService.SendEmailAsync(user.Email, "Confirm your Account", emailBody); // Заменили комментарий на переменную
                Console.WriteLine($"Confirmation email sent to {user.Email}. URL: {callbackUrl}");
            }
            catch (Exception emailEx) // Лучше ловить более специфичное исключение, если SmtpEmailService его определяет
            {
                Console.WriteLine($"CRITICAL: Failed to send confirmation email to {user.Email}: {emailEx.Message}. User account created but requires manual confirmation or resend.");
                // В этом случае, возможно, стоит откатить создание пользователя или пометить его как "ожидающий отправки email"
                // Или вернуть результат с ошибкой, чтобы UI мог это обработать
                // Удаление пользователя, если email не ушел (более строгий вариант):
                // await _userManager.DeleteAsync(user);
                // return new RegistrationResult(false, Errors: new List<string> { "Failed to send confirmation email. Please try registering again later." });

                // Вариант: пользователь создан, но email не ушел - сообщаем об этом
                return new RegistrationResult(true, UserId: user.Id, Errors: new List<string> { $"User '{user.Email}' registered, but confirmation email could not be sent. Please contact support or try resending later." });
            }

            return new RegistrationResult(true, UserId: user.Id);
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            // Логика инвалидации Refresh Token остается в ITokenService
            await _tokenService.InvalidateRefreshTokenAsync(refreshToken);
            return true;
        }

        public async Task<PasswordResetRequestResult> RequestPasswordResetAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                // Не раскрываем, существует ли пользователь или подтвержден ли email
                // Просто имитируем отправку письма для безопасности
                Console.WriteLine($"Password reset requested for non-existent or unconfirmed email: {email} (simulating success)");
                return new PasswordResetRequestResult(true);
            }

            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedCode = WebUtility.UrlEncode(code);

            string? serverBaseUrl = _configuration["Application:ServerBaseUrl"];
            if (string.IsNullOrEmpty(serverBaseUrl))
            {
                Console.WriteLine("Warning: Application:ServerBaseUrl (or relevant client URL) is not configured. Using default for password reset callback URL.");
                serverBaseUrl = "http://localhost:5076";
            }

            // Указываем путь к нашей HTML странице
            var clientResetPageSegment = "/reset-password-info.html"; 
            var callbackUrl = $"{serverBaseUrl}{clientResetPageSegment}?userId={user.Id}&code={encodedCode}";

            Console.WriteLine($"DEBUG: Password Reset Link generated: {callbackUrl}");
            Console.WriteLine($"DEBUG: For Password Reset - UserId: {user.Id}, Code (Token): {code}");
            
            try
            {
                string emailBody = $"Please reset your password by clicking here: <a href='{callbackUrl}'>Reset Password</a><br/>Or copy and paste this URL into your browser: {callbackUrl}";
                await _emailService.SendEmailAsync(user.Email, "Reset Your Password", emailBody); // Заменили комментарий
            }
             catch (Exception emailEx)
            {
                Console.WriteLine($"Failed to send password reset email to {user.Email}: {emailEx.Message}");
                // Продолжаем, как будто отправлено, для безопасности
            }
            return new PasswordResetRequestResult(true);
        }

        /*public async Task<PasswordResetResult> ResetPasswordAsync(string resetToken, string newPassword)
        {
            // В Identity токен сброса обычно привязан к UserId, который нужно получить из ссылки
            // или передать вместе с токеном. Сейчас у нас только токен.
            // Если токен содержит UserId - отлично. Иначе, модель Identity.ResetPasswordAsync(user, token, newPassword)
            // требует объекта user. Это слабое место в нашем текущем интерфейсе IAuthService.
            // Для простоты пока предположим, что `resetToken` - это тот, что сгенерировал Identity,
            // и мы должны найти пользователя по нему (что не стандартно для Identity токенов).

            // Правильный подход с Identity:
            // 1. Клиент переходит по ссылке, содержащей userId и code.
            // 2. Клиент отправляет userId, code и newPassword на сервер.
            // Поэтому изменим метод ResetPasswordAsync, чтобы он принимал userId.

            // --- ЭТОТ МЕТОД НУЖНО ПЕРЕДЕЛАТЬ, ЧТОБЫ ПРИНИМАТЬ UserId ---
            // Пока оставляю заглушку, показывающую, как это *могло бы* быть, если бы мы искали по токену
            // (что НЕ рекомендуется с Identity).
            // var user = await _context.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == resetToken); // Неправильно для Identity токенов

            // ПРАВИЛЬНЫЙ ПОДХОД:
            // Метод должен принимать userId: public async Task<PasswordResetResult> ResetPasswordAsync(string userId, string resetToken, string newPassword)
            // var user = await _userManager.FindByIdAsync(userId);
            // if (user == null) return new PasswordResetResult(false, Error: "User not found.");
            // var result = await _userManager.ResetPasswordAsync(user, resetToken, newPassword);
            // if (result.Succeeded) return new PasswordResetResult(true);
            // return new PasswordResetResult(false, Errors: result.Errors.Select(e => e.Description));

            Console.WriteLine("ResetPasswordAsync: Method signature needs update to include UserId for proper Identity usage.");
            return new PasswordResetResult(false, Error: "Password reset functionality needs rework for Identity.");
        }*/
        public async Task<PasswordResetResult> ResetPasswordAsync(string userId, string code, string newPassword)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code) || string.IsNullOrEmpty(newPassword) || newPassword.Length < 6)
            {
                return new PasswordResetResult(false, Error: "Требуется идентификатор пользователя, код сброса и действующий новый пароль.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new PasswordResetResult(false, Error: "Пользователь не найден.");
            }

            // Identity.ResetPasswordAsync сам обрабатывает декодирование токена
            var result = await _userManager.ResetPasswordAsync(user, code, newPassword);

            if (result.Succeeded)
            {
                return new PasswordResetResult(true);
            }
            else
            {
                return new PasswordResetResult(false, Errors: result.Errors.Select(e => e.Description));
            }
        }
        public async Task<EmailConfirmationResult> ConfirmEmailAsync(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return new EmailConfirmationResult(false, Error: "Требуется идентификатор пользователя и код подтверждения.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new EmailConfirmationResult(false, Error: "Пользователь не найден.");
            }

            // Identity.ConfirmEmailAsync сам обрабатывает декодирование токена
            var result = await _userManager.ConfirmEmailAsync(user, code);

            if (result.Succeeded)
            {
                return new EmailConfirmationResult(true);
            }
            else
            {
                return new EmailConfirmationResult(false, Errors: result.Errors.Select(e => e.Description));
            }
        }
        public async Task<ResendConfirmationEmailResult> ResendConfirmationEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // Не раскрываем информацию о существовании пользователя
                return new ResendConfirmationEmailResult(true, Message: "If an account with that email exists and is pending confirmation, a new email has been sent.");
            }

            if (await _userManager.IsEmailConfirmedAsync(user))
            {
                return new ResendConfirmationEmailResult(false, Message: "Этот адрес электронной почты уже подтвержден.", RequiresUserAction: true);
            }

            // Генерация нового кода и отправка письма
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedCode = WebUtility.UrlEncode(code);
            string? serverBaseUrl = _configuration["Application:ServerBaseUrl"];
            if (string.IsNullOrEmpty(serverBaseUrl))
            {
                Console.WriteLine("Warning: Application:ServerBaseUrl is not configured. Using default for resend email callback.");
                serverBaseUrl = "http://localhost:5076";
            }
            var callbackUrl = $"{serverBaseUrl}/api/Account/confirm-email?userId={user.Id}&code={encodedCode}";

            try
            {
                string emailBody = $"Please confirm your account by clicking this link: <a href='{callbackUrl}'>Confirm Account</a><br/>Or copy and paste this URL into your browser: {callbackUrl}";
                await _emailService.SendEmailAsync(user.Email, "Confirm your Account (Resend)", emailBody); // Заменили комментарий
                
                Console.WriteLine($"Re-sent confirmation email to {user.Email}. URL: {callbackUrl}");
                return new ResendConfirmationEmailResult(true, Message: "A new confirmation email has been sent to your email address.");
            }
            catch (Exception emailEx)
            {
                Console.WriteLine($"Failed to re-send confirmation email to {user.Email}: {emailEx.Message}");
                // Не раскрываем ошибку пользователю, но логируем
                return new ResendConfirmationEmailResult(false, Message: "An error occurred while trying to resend the confirmation email. Please try again later.");
            }
        }
    
    }
}