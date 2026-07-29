using System.Reflection;
using fakebookAuth;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace fakebookAuth.Tests;

public sealed class InternalUserContactTests
{
    [Fact]
    public async Task ActiveUserContact_ReturnsOnlyUserIdAndEmail()
    {
        var users = CreateRepository(new IdentityUser
        {
            UserId = 123,
            Email = "target@example.com",
            Status = AuthConstants.StatusActive
        }, out var repository);
        var controller = new InternalUsersController(null!, users);

        var action = await controller.GetUserContactAsync(123, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(action.Result);
        var contact = Assert.IsType<InternalUserContactResult>(ok.Value);
        Assert.Equal(123, contact.UserId);
        Assert.Equal("target@example.com", contact.Email);
        Assert.Equal(
            new[] { "Email", "UserId" },
            typeof(InternalUserContactResult).GetProperties().Select(property => property.Name).OrderBy(name => name));
        Assert.Equal(new long[] { 123 }, repository.RequestedUserIds);
    }

    [Theory]
    [InlineData(AuthConstants.StatusDisabled)]
    [InlineData(AuthConstants.StatusDeleted)]
    [InlineData(AuthConstants.StatusUnverified)]
    public async Task NonActiveUserContact_IsNotExposed(short status)
    {
        var users = CreateRepository(new IdentityUser
        {
            UserId = 123,
            Email = "hidden@example.com",
            Status = status
        }, out var repository);
        var controller = new InternalUsersController(null!, users);

        var action = await controller.GetUserContactAsync(123, CancellationToken.None);

        Assert.IsType<NotFoundResult>(action.Result);
        Assert.Equal(new long[] { 123 }, repository.RequestedUserIds);
    }

    [Fact]
    public async Task MissingUserContact_IsNotExposed()
    {
        var users = CreateRepository(null, out var repository);
        var controller = new InternalUsersController(null!, users);

        var action = await controller.GetUserContactAsync(123, CancellationToken.None);

        Assert.IsType<NotFoundResult>(action.Result);
        Assert.Equal(new long[] { 123 }, repository.RequestedUserIds);
    }

    [Fact]
    public async Task InvalidUserId_IsRejectedBeforeRepositoryAccess()
    {
        var users = CreateRepository(null, out var repository);
        var controller = new InternalUsersController(null!, users);

        var action = await controller.GetUserContactAsync(0, CancellationToken.None);

        Assert.IsType<BadRequestResult>(action.Result);
        Assert.Empty(repository.RequestedUserIds);
    }

    private static IUserRepository CreateRepository(IdentityUser? user, out UserRepositoryProxy proxy)
    {
        var repository = DispatchProxy.Create<IUserRepository, UserRepositoryProxy>();
        proxy = (UserRepositoryProxy)repository;
        proxy.User = user;
        return repository;
    }

    public class UserRepositoryProxy : DispatchProxy
    {
        public IdentityUser? User { get; set; }

        public List<long> RequestedUserIds { get; } = [];

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod?.Name == nameof(IUserRepository.FindByIdAsync) && args?.Length == 2)
            {
                var userId = Assert.IsType<long>(args[0]);
                RequestedUserIds.Add(userId);
                return Task.FromResult(User);
            }

            throw new InvalidOperationException($"Unexpected repository call: {targetMethod?.Name ?? "unknown"}.");
        }
    }
}
