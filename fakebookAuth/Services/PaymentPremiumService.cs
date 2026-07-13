using HotChocolate;
using Microsoft.Extensions.Options;

namespace fakebookAuth;

public interface IPaymentPremiumService
{
    Task<PaymentPremiumState> GetAsync(string userId, CancellationToken cancellationToken);
    Task<PaymentPremiumState> SetAsync(SetPaymentValidDateInput input, CancellationToken cancellationToken);
}

public sealed class PaymentPremiumService(
    IUserRepository users,
    IHttpContextAccessor httpContextAccessor,
    IOptions<PaymentOptions> options) : IPaymentPremiumService
{
    private const string PaymentSecretHeader = "X-Payment-Secret";

    public async Task<PaymentPremiumState> GetAsync(
        string userId,
        CancellationToken cancellationToken)
    {
        EnsurePaymentSecret();
        var parsedUserId = ParseUserId(userId);
        var user = await users.FindByIdAsync(parsedUserId, cancellationToken);
        if (user is null)
        {
            throw Error("User was not found.", "NOT_FOUND");
        }

        return new PaymentPremiumState(userId, user.ValidDate);
    }

    public async Task<PaymentPremiumState> SetAsync(
        SetPaymentValidDateInput input,
        CancellationToken cancellationToken)
    {
        EnsurePaymentSecret();
        var parsedUserId = ParseUserId(input.UserId);
        var stored = await users.SetValidDateAsync(parsedUserId, input.ValidDate, cancellationToken);
        if (stored is null)
        {
            throw Error("User was not found.", "NOT_FOUND");
        }

        return new PaymentPremiumState(input.UserId, stored);
    }

    private void EnsurePaymentSecret()
    {
        var expected = options.Value.InternalSharedSecret;
        var provided = httpContextAccessor.HttpContext?.Request.Headers[PaymentSecretHeader].ToString() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(expected) || !InternalSecretComparer.FixedTimeEquals(expected, provided))
        {
            throw Error("Payment service access is forbidden.", "FORBIDDEN");
        }
    }

    private static long ParseUserId(string value)
    {
        if (!long.TryParse(value, out var userId) || userId <= 0)
        {
            throw Error("User id is invalid.", "INVALID_INPUT");
        }

        return userId;
    }

    private static GraphQLException Error(string message, string code) =>
        new(ErrorBuilder.New().SetMessage(message).SetCode(code).Build());
}
