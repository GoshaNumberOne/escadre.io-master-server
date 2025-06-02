using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MasterServer.Configuration;
using MasterServer.Data;
using MasterServer.Data.Entities;
using MasterServer.Hubs;
using MasterServer.Services.Abstractions;
using MasterServer.Services.Implementations;
using Microsoft.AspNetCore.Identity;
using System.Text.Json;
using MasterServer.Configuration;
using MasterServer.Services.Abstractions;
using MasterServer.Services.Implementations;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
if (jwtSettings == null || string.IsNullOrEmpty(jwtSettings.SecretKey)) // Добавьте другие критичные проверки
{
    throw new InvalidOperationException("JWT SecretKey (and other critical settings) are missing or incomplete in configuration. Application cannot start.");
}
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

if (jwtSettings == null || string.IsNullOrEmpty(jwtSettings.SecretKey) || string.IsNullOrEmpty(jwtSettings.Issuer) || string.IsNullOrEmpty(jwtSettings.Audience))
{
    Console.WriteLine("Error: JWT settings are missing or incomplete in appsettings.json.");
}
if (string.IsNullOrEmpty(connectionString))
{
    // Замени Console.WriteLine на исключение, если строка подключения критична
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found in appsettings.json. Application cannot start.");
}
if (!string.IsNullOrEmpty(connectionString))
{
    builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(connectionString));
    builder.Services.AddScoped<IAuthService, AuthService>();
    builder.Services.AddScoped<ITokenService, JwtTokenService>();
    builder.Services.AddScoped<IUserService, UserService>();
    builder.Services.AddSingleton<IGameServerManager, InMemoryGameServerManager>();
    builder.Services.AddSingleton<IEmailService, SmtpEmailService>();
}

builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
var smtpSettings = builder.Configuration.GetSection("SmtpSettings").Get<SmtpSettings>();
if (smtpSettings == null || string.IsNullOrEmpty(smtpSettings.Host) /* ... и другие проверки ... */)
{
    Console.WriteLine("Error: SMTP settings are missing or incomplete.");
    // throw new InvalidOperationException("SMTP settings are missing or incomplete.");
}

builder.Services.AddSignalR()
    .AddJsonProtocol(options =>
    {
        options.PayloadSerializerOptions.PropertyNameCaseInsensitive = true;
        options.PayloadSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        // options.PayloadSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase; // Можно также явно указать, если нужно
    });

// Если вы также используете Controllers и хотите такое же поведение для них:
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
        //options.PayloadSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        // options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    });

// --- ДОБАВЛЕНИЕ IDENTITY ---
builder.Services.AddIdentityCore<User>(options =>
{
    // Настройки пароля
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false; // Можно изменить
    options.Password.RequiredLength = 6;

    // Настройки блокировки пользователя
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // Настройки пользователя
    options.User.RequireUniqueEmail = true; // Email должен быть уникальным

    // --- Настройки подтверждения Email ---
    options.SignIn.RequireConfirmedEmail = true; // Требовать подтвержденный email для входа
})
.AddEntityFrameworkStores<AppDbContext>().AddDefaultTokenProviders().AddSignInManager<SignInManager<User>>().AddErrorDescriber<RussianIdentityErrorDescriber>(); // Добавляет провайдеры для генерации токенов (для email, сброса пароля и т.д.)

if (jwtSettings != null && !string.IsNullOrEmpty(jwtSettings.SecretKey))
{/*
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
            ClockSkew = TimeSpan.Zero
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/masterhub"))
                {
                    context.Token = accessToken;
                }
                return Task.CompletedTask;
            }
        };
    });
    */builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
            ClockSkew = TimeSpan.Zero
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"]; // Получаем значение
                var path = context.HttpContext.Request.Path;

                Console.WriteLine($"!!!!!!!!!!!!!!!!! JWT OnMessageReceived: Path='{path}', Raw AccessToken from Query='{accessToken}' (Type: {accessToken.GetType()}) !!!!!!!!!!!!!!!!!");

                // Проверяем, существует ли ключ "access_token" в Query
                if (context.Request.Query.ContainsKey("access_token"))
                {
                    // Если значение токена null, пустая строка или состоит из пробелов,
                    // И это путь к нашему хабу,
                    // то мы НЕ хотим, чтобы middleware аутентификации вообще пытался его обработать.
                    if (string.IsNullOrWhiteSpace(accessToken.ToString()) && path.StartsWithSegments("/masterhub"))
                    {
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! JWT OnMessageReceived: AccessToken from Query is NULL or WHITESPACE for /masterhub. Actively ignoring/removing it. !!!!!!!!!!!!!!!!!");
                        // НЕ устанавливаем context.Token.
                        // Попытка удалить его из Query может быть сложной и небезопасной здесь.
                        // Вместо этого, давайте просто убедимся, что context.Token ТОЧНО НЕ УСТАНОВЛЕН.
                        // Если middleware все равно его подхватывает из оригинального Request.Query,
                        // то этот хак может не сработать.
                        // Главное - не делать context.Token = accessToken;
                    }
                    else if (!string.IsNullOrWhiteSpace(accessToken.ToString()) && path.StartsWithSegments("/masterhub"))
                    {
                        Console.WriteLine($"!!!!!!!!!!!!!!!!! JWT OnMessageReceived: Setting context.Token for /masterhub with token: '{accessToken}' !!!!!!!!!!!!!!!!!");
                        context.Token = accessToken.ToString();
                    }
                }
                else
                {
                    Console.WriteLine($"!!!!!!!!!!!!!!!!! JWT OnMessageReceived: 'access_token' key NOT FOUND in Query for path '{path}'. !!!!!!!!!!!!!!!!!");
                }
                return Task.CompletedTask;
            }
            // ...
        };
    });
}

builder.Services.AddAuthorization();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin",
        policy =>
        {
            policy.WithOrigins("http://localhost:3000", "https://your-web-client-domain.com")
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo { Title = "MasterServer API", Version = "v1" });
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your token in the text input below.\n\nExample: \"Bearer 12345abcdef\"",
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type=Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id="Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = Microsoft.OpenApi.Models.ParameterLocation.Header,
            },
            new List<string>()
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "MasterServer API v1"));
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseCors("AllowSpecificOrigin");

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.MapHub<MasterHub>("/masterhub");

app.Run();