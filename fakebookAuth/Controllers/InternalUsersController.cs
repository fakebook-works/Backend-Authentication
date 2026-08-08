using Microsoft.AspNetCore.Mvc;
using HotChocolate;

namespace fakebookAuth;

[ApiController]
[Route("internal/users")]
public sealed class InternalUsersController(IAuthService authService, IUserRepository userRepository) : ControllerBase
{
    [HttpGet("{userId:long}/contact")]
    public async Task<ActionResult<InternalUserContactResult>> GetUserContactAsync(
        long userId,
        CancellationToken cancellationToken)
    {
        if (userId <= 0)
        {
            return BadRequest();
        }

        var user = await userRepository.FindByIdAsync(userId, cancellationToken);
        if (user is null ||
            user.Status != AuthConstants.StatusActive ||
            !AuthInputValidation.TryNormalizeEmail(user.Email, out var email))
        {
            return NotFound();
        }

        return Ok(new InternalUserContactResult(user.UserId, email));
    }

    [HttpPost]
    [Consumes("application/json")]
    public async Task<ActionResult<AuthActionPayload>> CreateUserIdentityAsync(
        [FromBody] CreateUserIdentityInput? input,
        CancellationToken cancellationToken)
    {
        if (input is null)
        {
            return BadRequest(new AuthActionPayload(false, "User identity input is required."));
        }

        try
        {
            var result = await authService.CreateUserIdentityAsync(input, cancellationToken);
            return Ok(result);
        }
        catch (GraphQLException exception)
        {
            var message = exception.Errors.FirstOrDefault()?.Message ?? "User identity creation failed.";
            return BadRequest(new AuthActionPayload(false, message));
        }
    }

    [HttpDelete("{userId:long}")]
    public async Task<ActionResult<AuthActionPayload>> DeleteUserIdentityAsync(
        long userId,
        CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await authService.DeleteUserIdentityAsync(userId, cancellationToken));
        }
        catch (GraphQLException exception)
        {
            var message = exception.Errors.FirstOrDefault()?.Message ?? "User identity deletion failed.";
            return BadRequest(new AuthActionPayload(false, message));
        }
    }
}

public sealed record InternalUserContactResult(long UserId, string Email);
