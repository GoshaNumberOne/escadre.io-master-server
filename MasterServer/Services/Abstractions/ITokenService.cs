using System.Security.Claims;
using System.Threading.Tasks;

namespace MasterServer.Services.Abstractions
{
    public record TokenData(
        string AccessToken,
        DateTime AccessTokenExpiration,
        string RefreshToken
    );

    public record RefreshTokenResult(
        bool IsSuccess,
        string? NewAccessToken = null,
        DateTime? NewAccessTokenExpiration = null,
        string? NewRefreshToken = null, 
        string? Error = null
    );

    public record AccessTokenInfo(
        string AccessToken,
        DateTime AccessTokenExpiration
    );

    public interface ITokenService
    {
        Task<TokenData> GenerateTokensAsync(string userId, IEnumerable<Claim>? userClaims = null);
        Task<AccessTokenInfo> GenerateAnonymousAccessTokenAsync(string nickname);
        Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken);
        ClaimsPrincipal? ValidateAccessToken(string accessToken);
        Task InvalidateRefreshTokenAsync(string refreshToken);
    }
}