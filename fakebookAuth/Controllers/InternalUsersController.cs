using Microsoft.AspNetCore.Mvc;
using HotChocolate;

namespace fakebookAuth;

[ApiController]
[Route("internal/users")]
public sealed class InternalUsersController(IAuthService authService) : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<AuthActionPayload>> CreateUserIdentityAsync(
        [FromBody] CreateUserIdentityInput input,
        CancellationToken cancellationToken)
    {
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
}
