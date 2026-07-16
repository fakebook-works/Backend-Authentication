using Dapper;
using Npgsql;

namespace fakebookAuth;

public static class Program
{
    public static void Main(string[] args)
    {
        DefaultTypeMap.MatchNamesWithUnderscores = true;

        var builder = WebApplication.CreateBuilder(args);

        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            connectionString = builder.Configuration["POSTGRES_CONNECTION_STRING"];
        }

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Database connection string is required. Configure ConnectionStrings:DefaultConnection or POSTGRES_CONNECTION_STRING.");
        }

        builder.Services
            .AddOptions<JwtOptions>()
            .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.SigningKey), "Jwt:SigningKey is required.")
            .Validate(options => options.SigningKeyBytes >= 32, "Jwt:SigningKey must be at least 32 bytes.")
            .Validate(options => options.AccessTokenMinutes > 0, "Jwt:AccessTokenMinutes must be greater than zero.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<AuthOptions>()
            .Bind(builder.Configuration.GetSection(AuthOptions.SectionName))
            .Validate(options => options.RefreshTokenDays > 0, "Auth:RefreshTokenDays must be greater than zero.")
            .Validate(options => options.EmailVerificationMinutes > 0, "Auth:EmailVerificationMinutes must be greater than zero.")
            .Validate(options => options.PasswordResetMinutes > 0, "Auth:PasswordResetMinutes must be greater than zero.")
            .Validate(options => options.OtpCooldownSeconds >= 0, "Auth:OtpCooldownSeconds must be greater than or equal to zero.")
            .Validate(options => options.OtpFailureLimit > 0, "Auth:OtpFailureLimit must be greater than zero.")
            .Validate(options => options.OtpFailureWindowMinutes > 0, "Auth:OtpFailureWindowMinutes must be greater than zero.")
            .Validate(options => options.OtpResendLimit > 0, "Auth:OtpResendLimit must be greater than zero.")
            .Validate(options => options.OtpResendWindowMinutes > 0, "Auth:OtpResendWindowMinutes must be greater than zero.")
            .Validate(options => options.LoginFailureLimit > 0, "Auth:LoginFailureLimit must be greater than zero.")
            .Validate(options => options.LoginFailureWindowMinutes > 0, "Auth:LoginFailureWindowMinutes must be greater than zero.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.RefreshTokenCookieName), "Auth:RefreshTokenCookieName is required.")
            .Validate(options => options.RefreshTokenCookieName.All(character => character > 0x20 && character < 0x7f && character is not ';' and not ','), "Auth:RefreshTokenCookieName is invalid.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.RefreshTokenCookiePath), "Auth:RefreshTokenCookiePath is required.")
            .Validate(options => options.RefreshTokenCookieSameSite is "Strict" or "Lax" or "None", "Auth:RefreshTokenCookieSameSite must be Strict, Lax, or None.")
            .Validate(options => options.RefreshTokenCookieSameSite != "None" || options.RefreshTokenCookieSecure, "Auth:RefreshTokenCookieSecure must be true when SameSite=None.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<GatewayOptions>()
            .Bind(builder.Configuration.GetSection(GatewayOptions.SectionName))
            .Validate(
                options => options.InternalSharedSecretBytes == 0 || options.InternalSharedSecretBytes >= 32,
                "Gateway:InternalSharedSecret must be at least 32 bytes when configured.")
            .Validate(
                options => options.AuthenticationServiceSharedSecretBytes == 0 ||
                           options.AuthenticationServiceSharedSecretBytes >= 32,
                "Gateway:AuthenticationServiceSharedSecret must be at least 32 bytes when configured.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<PaymentOptions>()
            .Bind(builder.Configuration.GetSection(PaymentOptions.SectionName))
            .Validate(
                options => options.InternalSharedSecretBytes == 0 || options.InternalSharedSecretBytes >= 32,
                "Payment:InternalSharedSecret must be at least 32 bytes when configured.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<SmtpOptions>()
            .Bind(builder.Configuration.GetSection(SmtpOptions.SectionName))
            .Validate(options => !options.Enabled || options.IsConfigured, "SMTP must be fully configured when Smtp:Enabled is true.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<SnowflakeOptions>()
            .Bind(builder.Configuration.GetSection(SnowflakeOptions.SectionName))
            .Validate(options => options.WorkerId is >= 0 and <= 1023, "Snowflake:WorkerId must be between 0 and 1023.")
            .ValidateOnStart();

        builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
        builder.Services.AddSingleton<IAuthDatabaseReadinessProbe, PostgresAuthDatabaseReadinessProbe>();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddControllers();

        builder.Services.AddSingleton<ISnowflakeIdGenerator, SnowflakeIdGenerator>();
        builder.Services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
        builder.Services.AddSingleton<ITokenService, TokenService>();
        builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();

        builder.Services.AddScoped<IUserRepository, UserRepository>();
        builder.Services.AddScoped<ICredentialRepository, CredentialRepository>();
        builder.Services.AddScoped<IVerificationRepository, VerificationRepository>();
        builder.Services.AddScoped<ISessionRepository, SessionRepository>();
        builder.Services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        builder.Services.AddScoped<IAuthService, AuthService>();
        builder.Services.AddScoped<IPaymentPremiumService, PaymentPremiumService>();

        builder.Services
            .AddGraphQLServer("Authentication")
            .ModifyRequestOptions(options => options.IncludeExceptionDetails = builder.Environment.IsDevelopment())
            .AddQueryType<Query>()
            .AddMutationType<AuthMutations>();

        var app = builder.Build();

        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("RequestCorrelation");
        app.Use(async (context, next) =>
        {
            var correlationId = context.Request.Headers.TryGetValue("X-Correlation-ID", out var header) &&
                                !string.IsNullOrWhiteSpace(header.ToString())
                ? header.ToString()
                : Guid.NewGuid().ToString("N");

            context.Items["CorrelationId"] = correlationId;
            context.Response.Headers["X-Correlation-ID"] = correlationId;

            using (logger.BeginScope(new Dictionary<string, object?>
            {
                ["CorrelationId"] = correlationId
            }))
            {
                await next(context);
            }
        });

        app.MapGraphQL();
        app.MapControllers();
        app.MapGet("/health/live", AuthHealthEndpoints.Live);
        app.MapGet("/health/ready", AuthHealthEndpoints.ReadyAsync);
        app.MapGet("/", () => Results.Redirect("/graphql"));

        app.RunWithGraphQLCommands(args);
    }
}
