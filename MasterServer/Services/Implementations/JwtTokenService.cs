using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MasterServer.Configuration;
using MasterServer.Data;
using MasterServer.Data.Entities;
using MasterServer.Services.Abstractions;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace MasterServer.Services.Implementations
{
    public class JwtTokenService : ITokenService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly AppDbContext _context; 
        private readonly SymmetricSecurityKey _signingKey; 

        public JwtTokenService(IOptions<JwtSettings> jwtSettingsOptions, AppDbContext context)
        {
            //_jwtSettings = jwtSettingsOptions.Value;
            //_context = context;
            //_signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
                    Console.WriteLine("!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: START !!!!!!!!!!!!!!!!!"); // ДОБАВЬТЕ ЭТУ СТРОКУ
            try
            {
                _jwtSettings = jwtSettingsOptions.Value;
                if (_jwtSettings == null)
                {
                    Console.WriteLine("!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: _jwtSettings IS NULL after jwtSettingsOptions.Value !!!!!!!!!!!!!!!!!");
                    // Можно здесь выбросить исключение или как-то обработать, но для диагностики пока хватит лога
                }
                else
                {
                    // Выведем значения, чтобы точно их видеть
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: SecretKey IS '{_jwtSettings.SecretKey}' !!!!!!!!!!!!!!!!!");
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: Issuer IS '{_jwtSettings.Issuer}' !!!!!!!!!!!!!!!!!");
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: Audience IS '{_jwtSettings.Audience}' !!!!!!!!!!!!!!!!!");
                }

                _context = context;

                // Добавим явную проверку _jwtSettings и _jwtSettings.SecretKey ПЕРЕД использованием
                if (_jwtSettings == null || string.IsNullOrEmpty(_jwtSettings.SecretKey))
                {
                    Console.WriteLine("!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: _jwtSettings OR _jwtSettings.SecretKey IS NULL/EMPTY before GetBytes !!!!!!!!!!!!!!!!!");
                    // Это критическая ошибка, токен не создать. Выбрасываем исключение.
                    throw new InvalidOperationException("JwtSettings or JwtSettings.SecretKey is not configured correctly.");
                }

                _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
                Console.WriteLine("!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: _signingKey created successfully !!!!!!!!!!!!!!!!!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"!!!!!!!!!!!!!!!!! EXCEPTION IN JwtTokenService CONSTRUCTOR !!!!!!!!!!!!!!!!!");
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
                throw; // Перебрасываем исключение, чтобы DI не смог создать сервис, если конструктор упал
            }
            Console.WriteLine("!!!!!!!!!!!!!!!!! JwtTokenService CONSTRUCTOR: END !!!!!!!!!!!!!!!!!"); // ДОБАВЬТЕ ЭТУ СТРОКУ
        }

        public Task<TokenData> GenerateTokensAsync(string userId, IEnumerable<Claim>? userClaims = null)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (userClaims != null)
            {
                claims.AddRange(userClaims);
            }

            var accessTokenExpiration = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes);
            var accessToken = GenerateJwtToken(claims, accessTokenExpiration);

            var refreshToken = GenerateRefreshTokenString();
            var refreshTokenExpiration = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);

            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken, 
                ExpiryDate = refreshTokenExpiration,
                UserId = userId
            };
            _context.RefreshTokens.Add(refreshTokenEntity);

             var tokenData = new TokenData(
                AccessToken: accessToken,
                AccessTokenExpiration: accessTokenExpiration,
                RefreshToken: refreshToken
            );

            return Task.FromResult(tokenData);
        }

         public Task<AccessTokenInfo> GenerateAnonymousAccessTokenAsync(string nickname)
        {
             var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, $"anonymous_{Guid.NewGuid()}"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("nickname", nickname)
            };

            var accessTokenExpiration = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes);
            var accessToken = GenerateJwtToken(claims, accessTokenExpiration);

            var tokenInfo = new AccessTokenInfo(
                AccessToken: accessToken,
                AccessTokenExpiration: accessTokenExpiration
            );
             return Task.FromResult(tokenInfo);
        }


        public async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken)
        {
            var storedToken = await _context.RefreshTokens
                                      .Include(rt => rt.User) 
                                      .FirstOrDefaultAsync(rt => rt.Token == refreshToken && !rt.IsRevoked);

            if (storedToken == null || storedToken.ExpiryDate < DateTime.UtcNow)
            {
                return new RefreshTokenResult(false, Error: "Invalid or expired refresh token.");
            }
            storedToken.IsRevoked = true;
            _context.RefreshTokens.Update(storedToken);

            var newTokens = await GenerateTokensAsync(storedToken.UserId);

            await _context.SaveChangesAsync(); 

            return new RefreshTokenResult(
                IsSuccess: true,
                NewAccessToken: newTokens.AccessToken,
                NewAccessTokenExpiration: newTokens.AccessTokenExpiration,
                NewRefreshToken: newTokens.RefreshToken
            );
        }

        public ClaimsPrincipal? ValidateAccessToken(string accessToken)
        {
             var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(accessToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _signingKey,
                    ValidateIssuer = true,
                    ValidIssuer = _jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtSettings.Audience,
                    ValidateLifetime = true, 
                    ClockSkew = TimeSpan.Zero 
                }, out SecurityToken validatedToken);

                return principal;
            }
            catch (Exception) 
            {
                return null;
            }
        }

         public async Task InvalidateRefreshTokenAsync(string refreshToken)
        {
            var storedToken = await _context.RefreshTokens
                                      .FirstOrDefaultAsync(rt => rt.Token == refreshToken && !rt.IsRevoked);
            if (storedToken != null)
            {
                 storedToken.IsRevoked = true;
                 _context.RefreshTokens.Update(storedToken);
                 await _context.SaveChangesAsync();
            }
        }

        private string GenerateJwtToken(IEnumerable<Claim> claims, DateTime expires)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expires,
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256Signature)
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateRefreshTokenString()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}