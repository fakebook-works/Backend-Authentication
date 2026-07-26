using Dapper;
using Npgsql;

namespace fakebookAuth;

public static class Program
{
    public static void Main(string[] args)
    {
        DefaultTypeMap.MatchNamesWithUnderscores = true;

        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddInternalRequestSigning(
            builder.Configuration,
            "Gateway:AuthenticationServiceSharedSecret",
            "X-Internal-AuthenticationService-Secret");

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
            .Validate(options => options.PasswordHashWorkFactor is >= 10 and <= 14, "Auth:PasswordHashWorkFactor must be between 10 and 14.")
            .Validate(options => options.PasswordHashMaxConcurrency is >= 1 and <= 16, "Auth:PasswordHashMaxConcurrency must be between 1 and 16.")
            .Validate(options => options.PasswordHashQueueLimit is >= 0 and <= 256, "Auth:PasswordHashQueueLimit must be between 0 and 256.")
            .Validate(options => options.PasswordHashQueueTimeoutSeconds is >= 1 and <= 30, "Auth:PasswordHashQueueTimeoutSeconds must be between 1 and 30.")
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
                options => options.AuthenticationServiceSharedSecretBytes >= 32,
                "Gateway:AuthenticationServiceSharedSecret is required and must be at least 32 bytes.")
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

        // Authentication is never reachable from outside; it only receives traffic from the
        // gateway inside the private network, which emits a single authoritative
        // X-Forwarded-For entry. Without this every request looked like it came from the gateway
        // container, which silently turned per-IP login throttling into per-identifier
        // throttling — five failed attempts locked the real account owner out, and it could not
        // recover because the window only resets on a successful login. It also left every
        // session record showing a container address with no device, OS or browser.
        var forwardedHeaders = new Microsoft.AspNetCore.Builder.ForwardedHeadersOptions
        {
            ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor,
            ForwardLimit = 1
        };
        forwardedHeaders.KnownNetworks.Clear();
        forwardedHeaders.KnownProxies.Clear();
        foreach (var network in new[]
                 {
                     new Microsoft.AspNetCore.HttpOverrides.IPNetwork(System.Net.IPAddress.Parse("127.0.0.0"), 8),
                     new Microsoft.AspNetCore.HttpOverrides.IPNetwork(System.Net.IPAddress.Parse("10.0.0.0"), 8),
                     new Microsoft.AspNetCore.HttpOverrides.IPNetwork(System.Net.IPAddress.Parse("172.16.0.0"), 12),
                     new Microsoft.AspNetCore.HttpOverrides.IPNetwork(System.Net.IPAddress.Parse("192.168.0.0"), 16),
                     new Microsoft.AspNetCore.HttpOverrides.IPNetwork(System.Net.IPAddress.IPv6Loopback, 128)
                 })
        {
            forwardedHeaders.KnownNetworks.Add(network);
        }
        app.UseForwardedHeaders(forwardedHeaders);

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

        app.UseMiddleware<InternalRequestSignatureMiddleware>();

        app.MapGraphQL();
        app.MapControllers();
        app.MapGet("/health/live", AuthHealthEndpoints.Live);
        app.MapGet("/health/ready", AuthHealthEndpoints.ReadyAsync);
        app.MapGet("/", () => Results.Redirect("/graphql"));

        app.RunWithGraphQLCommands(args);
    }
}
